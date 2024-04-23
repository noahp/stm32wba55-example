//! @file
//!
//! A port of the Memfault Diagnostic GATT Service (MDS) to the STM32Cube FW WBA V1.3.0

#include "memfault/ports/ble/mds.h"

#include "common_blesvc.h"
#include "memfault/components.h"
#include "stm32_timer.h"

#if !defined(MEMFAULT_PROJECT_KEY)
  #error \
    "Memfault Project Key not configured. Please visit https://app.memfault.com/register?newProject"
#endif

#if BLE_CFG_MAX_NBR_CB <= 0
  #error "BLE_CFG_MAX_NBR_CB must be >=1 for MDS profile subscriber to SVCCTL_RegisterHandler()"
#endif

//! ATT Read, Write & Notification responses will have a 3 byte overhead
//! (1 Byte for Opcode + 2 bytes for length)
#define MDS_ATT_HEADER_OVERHEAD 3

//! Note: Attributes that are greater than the MTU size can be returned via long attribute reads
//! but the maximum allowed attribute value is 512 bytes. (See "3.2.9 Long attribute values" of
//! BLE v5.3 Core specification). In practice, all values returned by MDS should be much smaller
//! than this.
#define MDS_MAX_READ_LEN (512)

//! The interval to check for whether or not there is any new data to send
#ifndef MDS_POLL_INTERVAL_MS
  #define MDS_POLL_INTERVAL_MS (60 * 1000)
#endif

#ifndef MDS_MAX_DATA_URI_LENGTH
  #define MDS_MAX_DATA_URI_LENGTH 80
#endif

#ifndef MDS_URI_BASE
  //! i.e https://chunks.memfault.com/api/v0/chunks/
  #define MDS_URI_BASE \
    (MEMFAULT_HTTP_APIS_DEFAULT_SCHEME "://" MEMFAULT_HTTP_CHUNKS_API_HOST "/api/v0/chunks/")
#endif

#ifndef MDS_DYNAMIC_ACCESS_CONTROL
  #define MDS_DYNAMIC_ACCESS_CONTROL 0
#endif

//! Payload returned via a read to "MDS Supported Features Characteristic"
const static uint8_t s_mds_supported_features[] = {
  // no feature additions since the first spin of the profile
  0x0
};

//! Valid SNs used when sending data are 0-31
#define MDS_TOTAL_SEQ_NUMBERS 32

typedef enum {
  kMdsDataExportMode_StreamingDisabled = 0x00,
  kMdsDataExportMode_FullStreamingEnabled = 0x01,
} eMdsDataExportMode;

static uint8_t s_chunk_to_send[MDS_MAX_READ_LEN];

typedef MEMFAULT_PACKED_STRUCT {
  // bits 5-7: rsvd for future use
  // bits 0-4: sequence number
  uint8_t hdr;
  uint8_t chunk[];
} sMdsDataExportPayload;

typedef struct {
  uint16_t svc_id_h;

  uint16_t supported_features_h;
  uint16_t device_id_h;
  uint16_t data_uri_h;
  uint16_t auth_h;

  uint16_t chunk_val_h;
  uint16_t chunk_cccd_h;

  // Note: MDS only allows one active subscriber at any given time
  //
  // If a second connection attempts to subscribe while a first connection is already active, the
  // second request will be ignored.
  struct {
    bool active;
    eMdsDataExportMode mode;
    uint8_t seq_num;  // current sequence number to use
    uint16_t conn_idx;
  } subscriber;

  struct {
    uint16_t conn_idx;
    uint16_t mtu;
  } active_conn;

  sMdsDataExportPayload *payload;
  size_t chunk_len;

  UTIL_TIMER_Object_t timer;
} md_service_t;

static md_service_t s_mds;

typedef enum {
  // Error codes for ATT operations as defined in BT Core Specification
  kMdsAttError_Ok = 0x0,
  kMdsAttError_ReadNotPermitted = 0x02,
  kMdsAttError_WriteNotPermitted = 0x03,
  kMdsAttError_NotSupported = 0x06,

  kMdsAttError_AttributeNotFound = 0x0A,

  kMdsAttError_InvalidLength = 0x80 /* Application Specific Errors at >= 0x80 */,
  kMdsAttError_ClientAlreadySubscribed,
  kMdsAttError_InsufficientLength,
  kMdsAttError_ClientNotSubscribed,
} eMdsAttError;

#if !MDS_DYNAMIC_ACCESS_CONTROL
//! See mds.h header for more details, we recommend end user override this behavior for production
//! applications
MEMFAULT_WEAK bool mds_access_enabled(uint16_t connection_handle) {
  return true;
}
#endif

static SVCCTL_EvtAckStatus_t prv_handle_read_req(
    md_service_t *mds, const aci_gatt_read_permit_req_event_rp0 *read_req) {

  const void *value = NULL;
  size_t length = 0;
  uint16_t connection_handle = read_req->Connection_Handle;
  uint16_t att_handle = (read_req->Attribute_Handle - 1 /* att handle */);
  char uri[MDS_MAX_DATA_URI_LENGTH];
  struct MemfaultDeviceInfo info;


  if (att_handle == mds->supported_features_h) {
    value = &s_mds_supported_features;
    length = sizeof(s_mds_supported_features);
  } else if (att_handle == mds->data_uri_h) {
    memfault_platform_get_device_info(&info);
    strncpy(uri, MDS_URI_BASE, sizeof(uri) - 1);
    uri[sizeof(uri) - 1] = '\0';

    const size_t uri_base_length = strlen(MDS_URI_BASE);
    const size_t device_id_length = strlen(info.device_serial);
    const size_t total_length = uri_base_length + device_id_length;

    if (total_length > (sizeof(uri) - 1)) {
      MEMFAULT_LOG_ERROR("MDS: Not enough space allocated for URI");
      aci_gatt_deny_read(connection_handle, kMdsAttError_InsufficientLength);
      return SVCCTL_EvtAckFlowEnable;
    }

    strcpy(uri, MDS_URI_BASE);
    strcpy(&uri[uri_base_length], info.device_serial);
    uri[sizeof(uri) - 1] = '\0';
    value = uri;
    length = total_length;
  } else if (att_handle == mds->auth_h) {
    value = "Memfault-Project-Key:" MEMFAULT_PROJECT_KEY;
    length = strlen(value);
  } else if (att_handle == mds->device_id_h) {
    memfault_platform_get_device_info(&info);
    value = info.device_serial;
    length = strlen(value);
  } else {
    MEMFAULT_LOG_ERROR("%s: Read on unexpected handle: %d", __func__, att_handle);
    aci_gatt_deny_read(connection_handle, kMdsAttError_ReadNotPermitted);
    return SVCCTL_EvtAckFlowEnable;
  }

  if (length > MDS_MAX_READ_LEN) {
    // response exceeds minimum mtu size in length
    aci_gatt_deny_read(connection_handle, kMdsAttError_InsufficientLength);
    return SVCCTL_EvtAckFlowEnable;
  }

  tBleStatus rv = aci_gatt_update_char_value(mds->svc_id_h, att_handle, 0, length, value);
  if (rv != BLE_STATUS_SUCCESS) {
    MEMFAULT_LOG_ERROR("%s: Failed to update char %d, rv: 0x%x", __func__, att_handle, rv);
  }

  aci_gatt_allow_read(connection_handle);
  return SVCCTL_EvtAckFlowEnable;
}

static void prv_try_notify(md_service_t *mds, uint16_t conn_idx) {
  if ((!mds->subscriber.active) || (mds->subscriber.conn_idx != conn_idx)) {
    // caller has _not_ subscribed for chunk notifications so we do
    // not want to send the info to them
    MEMFAULT_LOG_INFO("Trying to send Memfault data but client hasn't subscribed");
    return;
  }

  if (mds->subscriber.mode == kMdsDataExportMode_StreamingDisabled) {
    // client has subscribed but not yet enabled data export
    return;
  }

  uint16_t mtu_size;
  if (conn_idx == mds->active_conn.conn_idx) {
    mtu_size = mds->active_conn.mtu;
  } else {
    MEMFAULT_LOG_ERROR("MTU size unknown, assuming default size");
    mtu_size = BLE_DEFAULT_ATT_MTU;
  }

  if ((mds->payload == NULL) && memfault_packetizer_data_available()) {
    mds->payload = (sMdsDataExportPayload *)&s_chunk_to_send[0];
    if (mds->payload != NULL) {
      mds->payload->hdr = mds->subscriber.seq_num & 0x1f;
      mds->chunk_len = mtu_size - MDS_ATT_HEADER_OVERHEAD - sizeof(*mds->payload);
      memfault_packetizer_get_chunk(&mds->payload->chunk[0], &mds->chunk_len);
    }
  }

  if (mds->chunk_len == 0) {
    // There's no more data, we were unable to allocate a buffer to hold a chunk or our send
    // request failed. Let's check to see if there is any more data / try again in
    // MDS_POLL_INTERVAL_MS
    UTIL_TIMER_SetPeriod(&mds->timer, MDS_POLL_INTERVAL_MS);
    UTIL_TIMER_Start(&mds->timer);
    return;
  }

  MEMFAULT_LOG_DEBUG("MDS: Sending %d byte chunk", mds->chunk_len);
  tBleStatus rv =
      aci_gatt_update_char_value(mds->svc_id_h, mds->chunk_val_h, 0,
                                 mds->chunk_len + sizeof(*mds->payload),
                                 (void *)mds->payload);
  if (rv != BLE_STATUS_SUCCESS) {
    // Likely means we've filled the internal stack buffers. We'll keep retrying until
    // data can succesfully be sent.
    MEMFAULT_LOG_ERROR("MDS: Failed to send chunk. rv=0x%x", rv);
  } else {
    // we succesfully sent the chunk so bump seq num and clear loaded chunk
    mds->subscriber.seq_num = (mds->subscriber.seq_num + 1) % MDS_TOTAL_SEQ_NUMBERS;
    mds->payload = NULL;
    mds->chunk_len = 0;
  }

  // Unfortunately, there's no event published from the stack when a notification is actually
  // published so we set a short timer to keep pumping chunk data until there is nothing
  // more to send
  UTIL_TIMER_SetPeriod(&mds->timer, 10);
  UTIL_TIMER_Start(&mds->timer);
}

static uint8_t prv_handle_data_export_write(
    md_service_t *mds, uint16_t conn_idx, uint16_t length, const uint8_t *value) {

  if (length != sizeof(uint8_t)) {
    MEMFAULT_LOG_ERROR("%s: bad length for handle: %d", __func__, length);
    return kMdsAttError_InvalidLength;
  }

  if ((!mds->subscriber.active) || (mds->subscriber.conn_idx != conn_idx)) {
    MEMFAULT_LOG_ERROR("%s: Client not subscribed, ignoring write request", __func__);
    return kMdsAttError_ClientNotSubscribed;
  }

  const eMdsDataExportMode cmd = (eMdsDataExportMode)value[0];

  switch (cmd) {
    case kMdsDataExportMode_StreamingDisabled:
    case kMdsDataExportMode_FullStreamingEnabled:
      break;
    default:
      return kMdsAttError_NotSupported;
  }

  mds->subscriber.mode = cmd;

  prv_try_notify(mds, conn_idx);
  return kMdsAttError_Ok;
}

static SVCCTL_EvtAckStatus_t prv_handle_write_req(
    md_service_t *mds, const aci_gatt_write_permit_req_event_rp0 *write_req) {

  uint16_t connection_handle = write_req->Connection_Handle;
  uint16_t att_handle = (write_req->Attribute_Handle - 1 /* offset to att handle */);

  const uint8_t write_status_nack = 0x1;

  if (att_handle != mds->chunk_val_h) {
    return SVCCTL_EvtNotAck;
  }

  if (!mds_access_enabled(write_req->Connection_Handle)) {
    aci_gatt_write_resp(connection_handle, att_handle, write_status_nack,
                        kMdsAttError_WriteNotPermitted, 0, NULL);
    return SVCCTL_EvtAckFlowEnable;
  }

  const uint8_t status = prv_handle_data_export_write(mds, connection_handle,
                                                      write_req->Data_Length, &write_req->Data[0]);

  //! Note: There's no way to control whether or not a notification is sent when we confirm the
  //! write response. The best we can do is force the write to be skipped but return a succesful
  //! error code. This will result in an "empty" notification being emitted.
  const tBleStatus rv = aci_gatt_write_resp(connection_handle, write_req->Attribute_Handle,
                                            write_status_nack, status, write_req->Data_Length,
                                            &write_req->Data[0]);

  if (rv != BLE_STATUS_SUCCESS) {
    MEMFAULT_LOG_ERROR("%s: Failed to confirm write: 0x%x", __func__, rv);
  }
  return SVCCTL_EvtAckFlowEnable;
}

static SVCCTL_EvtAckStatus_t prv_handle_cccd_write(
    md_service_t *mds, aci_gatt_attribute_modified_event_rp0 *modified_evt) {

  if (modified_evt->Attr_Handle != (mds->chunk_val_h + 2 /* offset to cccd */)) {
    return SVCCTL_EvtNotAck;
  }

  if (modified_evt->Offset != 0) {
    return SVCCTL_EvtNotAck;
  }

  if (modified_evt->Attr_Data_Length != sizeof(uint16_t)) {
    return SVCCTL_EvtNotAck;
  }

  uint8_t *value = &modified_evt->Attr_Data[0];
  const uint16_t cccd = value[0] | (value[1] << 8);;
  const bool subscribe_for_notifs = ((cccd & 0x1) != 0);
  if (!mds->subscriber.active) {
    // NB: we expect caller to subscribe for notifications each time they connect
    // so don't persist the mode across disconnects _and_ we only allow one
    // active subscription at a time.
    mds->subscriber.active = subscribe_for_notifs;
    mds->subscriber.conn_idx = modified_evt->Connection_Handle;
  } else if (mds->subscriber.conn_idx ==  modified_evt->Connection_Handle) {
    // handle case where client is subscribed (active) and has unsubscribed or re-subscribed for
    // some reason
    mds->subscriber.active = subscribe_for_notifs;
  } else {
    MEMFAULT_LOG_ERROR("One client is already subscribed");
  }

  return SVCCTL_EvtAckFlowEnable;
}

static void prv_handle_mtu_change(
    md_service_t *mds, aci_att_exchange_mtu_resp_event_rp0 *mtu_resp) {

  uint16_t conn_handle = mtu_resp->Connection_Handle;
  uint16_t mtu = mtu_resp->Server_RX_MTU;

  if (mds->active_conn.conn_idx == 0) {
    mds->active_conn.conn_idx = conn_handle;
  }

  if (mds->active_conn.conn_idx != conn_handle) {
    MEMFAULT_LOG_ERROR("Only track MTU for one active connection");
    return;
  }

  mds->active_conn.mtu = mtu;
}

static SVCCTL_EvtAckStatus_t prv_mds_event_handler(void *evt) {
  hci_event_pckt *evt_pckt = (hci_event_pckt *)(((hci_uart_pckt*)evt)->data);

  if (evt_pckt->evt != HCI_VENDOR_SPECIFIC_DEBUG_EVT_CODE) {
    MEMFAULT_LOG_INFO("Unexpected event_pckt->evt %d", evt_pckt->evt);
    return SVCCTL_EvtNotAck;
  }

  evt_blecore_aci *blecore_evt = (evt_blecore_aci*)evt_pckt->data;

  switch (blecore_evt->ecode) {

    case ACI_GATT_READ_PERMIT_REQ_VSEVT_CODE: {
      aci_gatt_read_permit_req_event_rp0 *read_req =
          (aci_gatt_read_permit_req_event_rp0 *)blecore_evt->data;
      return prv_handle_read_req(&s_mds, read_req);
    }

    case ACI_GATT_ATTRIBUTE_MODIFIED_VSEVT_CODE: {
      aci_gatt_attribute_modified_event_rp0 *modified_evt =
          (aci_gatt_attribute_modified_event_rp0 *)blecore_evt->data;
      prv_handle_cccd_write(&s_mds, modified_evt);
    }

    case ACI_GATT_WRITE_PERMIT_REQ_VSEVT_CODE: {
      aci_gatt_write_permit_req_event_rp0 *write_req =
          (aci_gatt_write_permit_req_event_rp0 *)blecore_evt->data;
      return prv_handle_write_req(&s_mds, write_req);
    }

    case ACI_ATT_EXCHANGE_MTU_RESP_VSEVT_CODE: {
      aci_att_exchange_mtu_resp_event_rp0 *mtu_resp =
          (aci_att_exchange_mtu_resp_event_rp0 *)blecore_evt->data;
      prv_handle_mtu_change(&s_mds, mtu_resp);
    }

    default:
      break;

  }

  return SVCCTL_EvtNotAck;
}

static void prv_handle_disconnected_evt(md_service_t *mds,
                                        const hci_disconnection_complete_event_rp0 *disconn_evt ) {
  if (mds->subscriber.active && (mds->subscriber.conn_idx == disconn_evt->Connection_Handle)) {
    mds->subscriber.active = false;
    mds->subscriber.conn_idx = 0;
    mds->subscriber.seq_num = 0;
    mds->subscriber.mode = kMdsDataExportMode_StreamingDisabled;

    mds->active_conn.conn_idx = 0;
    mds->active_conn.mtu = 0;
    UTIL_TIMER_Stop(&mds->timer);
    aci_gatt_update_char_value(mds->svc_id_h, mds->chunk_val_h, 0, 0, NULL);
  }
}

static SVCCTL_EvtAckStatus_t prv_mds_handler(void *pckt) {
  hci_event_pckt *hci_pckt = (hci_event_pckt*) ((hci_uart_pckt *) pckt)->data;

  switch (hci_pckt->evt) {

    case HCI_DISCONNECTION_COMPLETE_EVT_CODE: {
      hci_disconnection_complete_event_rp0 *disconn_evt =
          (hci_disconnection_complete_event_rp0 *) hci_pckt->data;
      prv_handle_disconnected_evt(&s_mds, disconn_evt);
      break;
    }
    default:
      break;
  }

  return SVCCTL_EvtNotAck;
}

//! A timer service run that periodically checks to see if there
//! is any new data to send to Memfault while connected
static void prv_mds_timer_callback(MEMFAULT_UNUSED void *arg) {
  prv_try_notify(&s_mds, s_mds.subscriber.conn_idx);
}

void *mds_boot(void) {
  UTIL_TIMER_Create(&s_mds.timer,
                    1000,
                    UTIL_TIMER_ONESHOT,
                    &prv_mds_timer_callback, 0);


  SVCCTL_RegisterSvcHandler(prv_mds_event_handler);
  SVCCTL_RegisterHandler(prv_mds_handler);

  const uint16_t num_includes = 0;
  const uint16_t num_characteristics = 6;
  const uint16_t num_descriptors = 1;
  const uint8_t mds_service_uuid[] = {
    0x36, 0x84, 0xbd, 0x4e,0x2f, 0x72, 0x71, 0xa3, 0x07, 0x40, 0xa5, 0xf6,
    0x00, 0x00, 0x22, 0x54
  };
  tBleStatus rv = aci_gatt_add_service(UUID_TYPE_128,
                                       (Service_UUID_t *)&mds_service_uuid,
                                       PRIMARY_SERVICE,
                                       num_includes + num_characteristics * 2 + num_descriptors,
                                       &s_mds.svc_id_h);
  MEMFAULT_ASSERT(rv == BLE_STATUS_SUCCESS);


  const uint8_t mds_supported_features_char[] = {
    0x36, 0x84, 0xbd, 0x4e,0x2f, 0x72, 0x71, 0xa3, 0x07, 0x40, 0xa5, 0xf6,
    0x01, 0x00, 0x22, 0x54
  };
  rv = aci_gatt_add_char(s_mds.svc_id_h,
                         UUID_TYPE_128,
                         (Char_UUID_t *)&mds_supported_features_char[0],
                         sizeof(s_mds_supported_features),
                         CHAR_PROP_READ,
                         ATTR_PERMISSION_NONE /* ? */,
                         GATT_NOTIFY_READ_REQ_AND_WAIT_FOR_APPL_RESP,
                         10 /* encryKeySize */,
                         0x00 /* fixed length */,
                         &s_mds.supported_features_h);
  MEMFAULT_ASSERT(rv == BLE_STATUS_SUCCESS);

  const uint8_t mds_device_id_char[] = {
    0x36, 0x84, 0xbd, 0x4e,0x2f, 0x72, 0x71, 0xa3, 0x07, 0x40, 0xa5, 0xf6,
    0x02, 0x00, 0x22, 0x54
  };
  rv = aci_gatt_add_char(s_mds.svc_id_h,
                         UUID_TYPE_128,
                         (Char_UUID_t *)&mds_device_id_char[0],
                         MEMFAULT_DEVICE_INFO_MAX_STRING_SIZE,
                         CHAR_PROP_READ,
                         ATTR_PERMISSION_NONE /* ? */,
                         GATT_NOTIFY_READ_REQ_AND_WAIT_FOR_APPL_RESP,
                         10 /* encryKeySize */,
                         0x01 /* variable */,
                         &s_mds.device_id_h);
  MEMFAULT_ASSERT(rv == BLE_STATUS_SUCCESS);

  const uint8_t mds_data_uri_char[] = {
    0x36, 0x84, 0xbd, 0x4e,0x2f, 0x72, 0x71, 0xa3, 0x07, 0x40, 0xa5, 0xf6,
    0x03, 0x00, 0x22, 0x54
  };
  rv = aci_gatt_add_char(s_mds.svc_id_h,
                         UUID_TYPE_128,
                         (Char_UUID_t *)&mds_data_uri_char[0],
                         MDS_MAX_DATA_URI_LENGTH,
                         CHAR_PROP_READ,
                         ATTR_PERMISSION_NONE /* ? */,
                         GATT_NOTIFY_READ_REQ_AND_WAIT_FOR_APPL_RESP,
                         10 /* encryKeySize */,
                         0x01 /* variable */,
                         &s_mds.data_uri_h);
  MEMFAULT_ASSERT(rv == BLE_STATUS_SUCCESS);

  const uint8_t mds_auth_char[] = {
    0x36, 0x84, 0xbd, 0x4e,0x2f, 0x72, 0x71, 0xa3, 0x07, 0x40, 0xa5, 0xf6,
    0x04, 0x00, 0x22, 0x54
  };
  rv = aci_gatt_add_char(s_mds.svc_id_h,
                         UUID_TYPE_128,
                         (Char_UUID_t *)&mds_auth_char[0],
                         64, /* sizeof("Memfault-Project-Key:${PROJECT_KEY}") */
                         CHAR_PROP_READ,
                         ATTR_PERMISSION_NONE /* ? */,
                         GATT_NOTIFY_READ_REQ_AND_WAIT_FOR_APPL_RESP,
                         10 /* encryKeySize */,
                         0x01 /* variable */,
                         &s_mds.auth_h);
  MEMFAULT_ASSERT(rv == BLE_STATUS_SUCCESS);


  const uint8_t mds_chunk_val_char[] = {
    0x36, 0x84, 0xbd, 0x4e,0x2f, 0x72, 0x71, 0xa3, 0x07, 0x40, 0xa5, 0xf6,
    0x05, 0x00, 0x22, 0x54
  };
  rv = aci_gatt_add_char(s_mds.svc_id_h,
                         UUID_TYPE_128,
                         (Char_UUID_t *)&mds_chunk_val_char[0],
                         MDS_MAX_READ_LEN,
                         CHAR_PROP_WRITE | CHAR_PROP_NOTIFY ,
                         ATTR_PERMISSION_NONE /* ? */,
                         GATT_NOTIFY_WRITE_REQ_AND_WAIT_FOR_APPL_RESP,
                         10 /* encryKeySize */,
                         0x01 /* variable */,
                         &s_mds.chunk_val_h);
  MEMFAULT_ASSERT(rv == BLE_STATUS_SUCCESS);

  return &s_mds;
}
