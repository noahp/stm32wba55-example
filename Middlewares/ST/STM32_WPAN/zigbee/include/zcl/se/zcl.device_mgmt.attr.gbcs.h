/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/se/zcl.device_mgmt.h"

#ifndef ZCL_DEVICE_MGMT_ATTR_CALLBACK
# define ZCL_DEVICE_MGMT_ATTR_CALLBACK              NULL
# define ZCL_DEVICE_MGMT_ATTR_FLAGS                 ZCL_ATTR_FLAG_NONE
/* By default, disable reporting */
# define ZCL_DEVICE_MGMT_ATTR_REPORT_INTVL_MIN      0x0000U
# define ZCL_DEVICE_MGMT_ATTR_REPORT_INTVL_MAX      0xffffU

#else
# ifndef ZCL_DEVICE_MGMT_ATTR_FLAGS
/* If callback is defined, must also define read/write callback flags:
 * ZCL_ATTR_FLAG_CB_READ | ZCL_ATTR_FLAG_CB_WRITE */
#  error "ZCL_DEVICE_MGMT_ATTR_FLAGS not defined"
# endif
# ifndef ZCL_DEVICE_MGMT_ATTR_REPORT_INTVL_MIN
#  error "ZCL_DEVICE_MGMT_ATTR_REPORT_INTVL_MIN not defined"
# endif
# ifndef ZCL_DEVICE_MGMT_ATTR_REPORT_INTVL_MAX
#  error "ZCL_DEVICE_MGMT_ATTR_REPORT_INTVL_MAX not defined"
# endif
#endif

static const struct ZbZclAttrT zcl_device_mgmt_server_gbcs_attr_list[] = {
    {
        ZCL_DEVICE_MGMT_SVR_ATTR_ProviderName, ZCL_DATATYPE_STRING_OCTET, ZCL_DEVICE_MGMT_ATTR_FLAGS, 16,
        ZCL_DEVICE_MGMT_ATTR_CALLBACK, {0, 0},
        {ZCL_DEVICE_MGMT_ATTR_REPORT_INTVL_MIN, ZCL_DEVICE_MGMT_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_DEVICE_MGMT_SVR_ATTR_ProviderContactDetails, ZCL_DATATYPE_STRING_OCTET, ZCL_DEVICE_MGMT_ATTR_FLAGS, 19,
        ZCL_DEVICE_MGMT_ATTR_CALLBACK, {0, 0},
        {ZCL_DEVICE_MGMT_ATTR_REPORT_INTVL_MIN, ZCL_DEVICE_MGMT_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_DEVICE_MGMT_SVR_ATTR_LowMediumThreshold, ZCL_DATATYPE_UNSIGNED_32BIT, ZCL_DEVICE_MGMT_ATTR_FLAGS, 0,
        ZCL_DEVICE_MGMT_ATTR_CALLBACK, {0, 0},
        {ZCL_DEVICE_MGMT_ATTR_REPORT_INTVL_MIN, ZCL_DEVICE_MGMT_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_DEVICE_MGMT_SVR_ATTR_MediumHighThreshold, ZCL_DATATYPE_UNSIGNED_32BIT, ZCL_DEVICE_MGMT_ATTR_FLAGS, 0,
        ZCL_DEVICE_MGMT_ATTR_CALLBACK, {0, 0},
        {ZCL_DEVICE_MGMT_ATTR_REPORT_INTVL_MIN, ZCL_DEVICE_MGMT_ATTR_REPORT_INTVL_MAX}
    },
};
