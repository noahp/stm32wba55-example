#pragma once

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
//! @brief
//! Platform overrides for the default configuration settings in the memfault-firmware-sdk.
//! Default configuration settings can be found in "memfault/config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MEMFAULT_USE_GNU_BUILD_ID 1
#define MEMFAULT_PLATFORM_HAS_LOG_CONFIG 1

// For test purposes, check for new data every 30 seconds
#define MDS_POLL_INTERVAL_MS 30

// Should be generating one heartbeat / hour but for test purposes we will use a faster interval
#define MEMFAULT_METRICS_HEARTBEAT_INTERVAL_SECS 60

// TODO: Add Project API Key
#define MEMFAULT_PROJECT_KEY "FIXME"

#ifdef __cplusplus
}
#endif
