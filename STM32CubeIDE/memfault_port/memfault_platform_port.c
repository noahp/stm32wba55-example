//! @file
//!
//! Copyright 2024 Memfault, Inc
//!
//! Licensed under the Apache License, Version 2.0 (the "License");
//! you may not use this file except in compliance with the License.
//! You may obtain a copy of the License at
//!
//!     http://www.apache.org/licenses/LICENSE-2.0
//!
//! Unless required by applicable law or agreed to in writing, software
//! distributed under the License is distributed on an "AS IS" BASIS,
//! WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//! See the License for the specific language governing permissions and
//! limitations under the License.
//!
//! Glue layer between the Memfault SDK and the underlying platform
//!
//! TODO: Fill in FIXMEs below for your platform

#include <stdbool.h>

#include "memfault/components.h"
#include "memfault/ports/reboot_reason.h"
#include "stm32_timer.h"
#include "stm32wbaxx_hal.h"
#include "stm32wbaxx_ll_utils.h"

static char prv_nib_to_hex_ascii(uint8_t val) {
  return val < 10 ? (char)val + '0' : (char)(val - 10) + 'A';
}

#define MEMFAULT_UID_SIZE_IN_WORDS (3)
#define MEMFAULT_UID_SIZE_IN_BYTES (MEMFAULT_UID_SIZE_IN_WORDS * 4)
#define MEMFAULT_UID_SIZE_IN_ASCII (MEMFAULT_UID_SIZE_IN_BYTES * 2)

static char s_device_serial[MEMFAULT_UID_SIZE_IN_ASCII + 1] = { 0 };  // +1 for null

static char *prv_get_device_serial(void) {
  uint32_t uid[] = {
    LL_GetUID_Word0(),
    LL_GetUID_Word1(),
    LL_GetUID_Word1()
  };
  uint8_t *byte_reader = (uint8_t *)uid;
  char *serial_write_ptr = &s_device_serial[0];

  for (size_t i = 0; i < MEMFAULT_UID_SIZE_IN_BYTES; i++) {
    uint8_t c = byte_reader[i];
    *serial_write_ptr++ = prv_nib_to_hex_ascii(c >> 4);
    *serial_write_ptr++ = prv_nib_to_hex_ascii(c & 0xf);
  }
  *serial_write_ptr = 0;  // null terminate the ascii string
  return s_device_serial;
}


void memfault_platform_get_device_info(sMemfaultDeviceInfo *info) {
  // IMPORTANT: All strings returned in info must be constant
  // or static as they will be used _after_ the function returns

  // See https://mflt.io/version-nomenclature for more context
  *info = (sMemfaultDeviceInfo){
    // An ID that uniquely identifies the device in your fleet
    // (i.e serial number, mac addr, chip id, etc)
    // Regular expression defining valid device serials: ^[-a-zA-Z0-9_]+$
    .device_serial = prv_get_device_serial(),
    // A name to represent the firmware running on the MCU.
    // (i.e "ble-fw", "main-fw", or a codename for your project)
    .software_type = "app-fw",
    // The version of the "software_type" currently running.
    // "software_type" + "software_version" must uniquely represent
    // a single binary
    .software_version = "1.0.0",
    // The revision of hardware for the device. This value must remain
    // the same for a unique device.
    // (i.e evt, dvt, pvt, or rev1, rev2, etc)
    // Regular expression defining valid hardware versions: ^[-a-zA-Z0-9_\.\+]+$
    .hardware_version = "dvt1",
  };
}

//! Last function called after a coredump is saved. Should perform
//! any final cleanup and then reset the device
void memfault_platform_reboot(void) {
  HAL_NVIC_SystemReset();
  __builtin_unreachable();
}

bool memfault_platform_time_get_current(sMemfaultCurrentTime *time) {
  // !FIXME: If the device tracks real time, update 'unix_timestamp_secs' with seconds since epoch
  // This will cause events logged by the SDK to be timestamped on the device rather than when they
  // arrive on the server
  *time = (sMemfaultCurrentTime){
    .type = kMemfaultCurrentTimeType_UnixEpochTimeSec,
    .info = { .unix_timestamp_secs = 0 },
  };

  // !FIXME: If device does not track time, return false, else return true if time is valid
  return false;
}

uint64_t memfault_platform_get_time_since_boot_ms(void) {
  return (HAL_GetTick() / (HAL_GetTickFreq() * 1024));
}

static UTIL_TIMER_Object_t  s_hb_timer;
static MemfaultPlatformTimerCallback *s_metric_timer_cb = NULL;

static void prv_heartbeat_timer_callback(void *arg) {
  s_metric_timer_cb();
}

bool memfault_platform_metrics_timer_boot(uint32_t period_sec,
                                          MemfaultPlatformTimerCallback *callback) {
  UTIL_TIMER_Create(&s_hb_timer,
                    MEMFAULT_METRICS_HEARTBEAT_INTERVAL_SECS * 1000,
                    UTIL_TIMER_PERIODIC,
                    &prv_heartbeat_timer_callback, 0);
  UTIL_TIMER_Start(&s_hb_timer);

  s_metric_timer_cb = callback;
  return true;
}

MEMFAULT_PUT_IN_SECTION(".noinit.mflt_reboot_info")
static uint8_t s_reboot_tracking[MEMFAULT_REBOOT_TRACKING_REGION_SIZE];

void memfault_platform_reboot_tracking_boot(void) {
  sResetBootupInfo reset_info = { 0 };
  memfault_reboot_reason_get(&reset_info);
  memfault_reboot_tracking_boot(s_reboot_tracking, &reset_info);
}

size_t memfault_platform_sanitize_address_range(void *start_addr, size_t desired_size) {
  const struct {
    uint32_t start_addr;
    size_t length;
  } s_mcu_mem_regions[] = {
    {
      .start_addr = SRAM1_BASE_NS, .length = SRAM1_SIZE,
      .start_addr = SRAM2_BASE_NS, .length = SRAM2_SIZE,
    },
  };

  for (size_t i = 0; i < MEMFAULT_ARRAY_SIZE(s_mcu_mem_regions); i++) {
    const uint32_t lower_addr = s_mcu_mem_regions[i].start_addr;
    const uint32_t upper_addr = lower_addr + s_mcu_mem_regions[i].length;
    if ((uint32_t)start_addr >= lower_addr && ((uint32_t)start_addr < upper_addr)) {
      return MEMFAULT_MIN(desired_size, upper_addr - (uint32_t)start_addr);
    }
  }

  return 0;
}

int memfault_platform_boot(void) {
  memfault_build_info_dump();
  memfault_device_info_dump();
  memfault_platform_reboot_tracking_boot();

  // initialize the event storage buffer
  static uint8_t s_event_storage[1024];
  const sMemfaultEventStorageImpl *evt_storage =
    memfault_events_storage_boot(s_event_storage, sizeof(s_event_storage));

  // configure trace events to store into the buffer
  memfault_trace_event_boot(evt_storage);

  // record the current reboot reason
  memfault_reboot_tracking_collect_reset_info(evt_storage);

  // configure the metrics component to store into the buffer
  sMemfaultMetricBootInfo boot_info = {
    .unexpected_reboot_count = memfault_reboot_tracking_get_crash_count(),
  };
  memfault_metrics_boot(evt_storage, &boot_info);

  MEMFAULT_LOG_INFO("Memfault Initialized!");

  return 0;
}
