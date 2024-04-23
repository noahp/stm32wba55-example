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
//! Logging depends on how your configuration does logging. See
//! https://docs.memfault.com/docs/mcu/self-serve/#logging-dependency

#ifdef __cplusplus
extern "C" {
#endif

  // TODO

#include "log_module.h"

#define _LOG_IMPL(lvl, fmt, ...)                                        \
  do {                                                                  \
    LOG_INFO_APP(fmt "\r\n", ## __VA_ARGS__ );                                   \
  } while (0)


#define MEMFAULT_LOG_DEBUG(fmt, ...) _LOG_IMPL(kMemfaultPlatformLogLevel_Debug, fmt, ## __VA_ARGS__)
#define MEMFAULT_LOG_INFO(fmt, ...)  _LOG_IMPL(kMemfaultPlatformLogLevel_Info, fmt, ## __VA_ARGS__)
#define MEMFAULT_LOG_WARN(fmt, ...)  _LOG_IMPL(kMemfaultPlatformLogLevel_Warning, fmt, ## __VA_ARGS__)
#define MEMFAULT_LOG_ERROR(fmt, ...) _LOG_IMPL(kMemfaultPlatformLogLevel_Error, fmt, ## __VA_ARGS__)


#define MEMFAULT_LOG_RAW(fmt, ...) _LOG_IMPL(kMemfaultPlatformLogLevel_Debug, fmt "\n", ## __VA_ARGS__)

#ifdef __cplusplus
}
#endif
