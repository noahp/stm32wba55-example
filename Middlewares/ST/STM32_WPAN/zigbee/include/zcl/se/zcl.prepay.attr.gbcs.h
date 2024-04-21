/* Copyright [2009 - 2023] Exegin Technologies Limited. All rights reserved. */

#include "zcl/se/zcl.prepay.h"

#ifndef ZCL_PREPAY_ATTR_CALLBACK
# define ZCL_PREPAY_ATTR_CALLBACK                   NULL
# define ZCL_PREPAY_ATTR_FLAGS                      ZCL_ATTR_FLAG_NONE
# define ZCL_PREPAY_ATTR_FLAGS_WRITABLE             ZCL_ATTR_FLAG_WRITABLE
/* By default, disable reporting */
# define ZCL_PREPAY_ATTR_REPORT_INTVL_MIN           0x0000U
# define ZCL_PREPAY_ATTR_REPORT_INTVL_MAX           0xffffU

#else
# ifndef ZCL_PREPAY_ATTR_FLAGS
/* If callback is defined, must also define read/write callback flags:
 * ZCL_ATTR_FLAG_CB_READ | ZCL_ATTR_FLAG_CB_WRITE */
#  error "ZCL_PREPAY_ATTR_FLAGS not defined"
# endif
/* NOTE: ZCL_PREPAY_ATTR_FLAGS_WRITABLE currently not used in this file. */
# ifndef ZCL_PREPAY_ATTR_FLAGS_WRITABLE
/* If callback is defined, must also define read/write callback flags:
 * ZCL_ATTR_FLAG_CB_READ | ZCL_ATTR_FLAG_CB_WRITE
 * as well as ZCL_ATTR_FLAG_WRITABLE in this case. */
#  error "ZCL_PREPAY_ATTR_FLAGS_WRITABLE not defined"
# endif
# ifndef ZCL_PREPAY_ATTR_REPORT_INTVL_MIN
#  error "ZCL_PREPAY_ATTR_REPORT_INTVL_MIN not defined"
# endif
# ifndef ZCL_PREPAY_ATTR_REPORT_INTVL_MAX
#  error "ZCL_PREPAY_ATTR_REPORT_INTVL_MAX not defined"
# endif
#endif

#ifndef ZCL_PREPAY_ATTR_CALLBACK_CREDIT_REMAINING
# define ZCL_PREPAY_ATTR_CALLBACK_CREDIT_REMAINING  ZbZclPrepayServerAttrCreditRemainingWriteCb
# define ZCL_PREPAY_ATTR_FLAGS_CREDIT_REMAINING     ZCL_ATTR_FLAG_CB_WRITE
#else
# ifndef ZCL_PREPAY_ATTR_FLAGS_CREDIT_REMAINING
#  error "ZCL_PREPAY_ATTR_FLAGS_CREDIT_REMAINING not defined"
# endif
#endif

static const struct ZbZclAttrT zcl_prepay_server_gbcs_attr_list[] = {
    {
        ZCL_PREPAY_SVR_ATTR_PAYMENT_CONTROL_CONFIG, ZCL_DATATYPE_BITMAP_16BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_CREDIT_REMAINING, ZCL_DATATYPE_SIGNED_32BIT,
        ZCL_PREPAY_ATTR_FLAGS_CREDIT_REMAINING, 0, ZCL_PREPAY_ATTR_CALLBACK_CREDIT_REMAINING,
        {0, 0}, {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_EMERG_CREDIT_REMAINING, ZCL_DATATYPE_SIGNED_32BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_ACCUMULATED_DEBT, ZCL_DATATYPE_SIGNED_32BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_OVERALL_DEBT_CAP, ZCL_DATATYPE_SIGNED_32BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_EMERG_CREDIT_ALLOWANCE, ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_EMERG_CREDIT_THRESHOLD, ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_LOW_CREDIT_WARNING, ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_CUT_OFF_VALUE, ZCL_DATATYPE_SIGNED_32BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_ALARM_STATUS, ZCL_DATATYPE_BITMAP_16BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_HIST_CCTION_FORMAT, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_CONSUMPTION_UNIT_OF_MEASURE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_CURRENCY_SCALING_FACTOR, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_CURRENCY, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    /* ZCL_PREPAY_SVR_ATTR_DEBT_AMOUNT_N,  (1 to 3) */
    {
        ZCL_PREPAY_SVR_ATTR_DEBT_AMOUNT_N(1), ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0,
        ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_DEBT_AMOUNT_N(2), ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_DEBT_AMOUNT_N(3), ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    /* ZCL_PREPAY_SVR_ATTR_DEBT_REC_FREQ_N,  (1 to 2) */
    {
        ZCL_PREPAY_SVR_ATTR_DEBT_REC_FREQ_N(1), ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_DEBT_REC_FREQ_N(2), ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    /* ZCL_PREPAY_SVR_ATTR_DEBT_REC_AMOUNT_N,  (1 to 2) */
    {
        ZCL_PREPAY_SVR_ATTR_DEBT_REC_AMOUNT_N(1), ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_DEBT_REC_AMOUNT_N(2), ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    /* ZCL_PREPAY_SVR_ATTR_DEBT_REC_TOPUP_PERCENT_N (just #3 ?) */
    {
        ZCL_PREPAY_SVR_ATTR_DEBT_REC_TOPUP_PERCENT_N(3), ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    /* ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_DAY_N (0 to 8) */
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_DAY_N(0), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_DAY_N(1), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_DAY_N(2), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_DAY_N(3), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_DAY_N(4), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_DAY_N(5), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_DAY_N(6), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_DAY_N(7), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_DAY_N(8), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    /* ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_WEEK_N (0 to 5) */
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_WEEK_N(0), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_WEEK_N(1), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_WEEK_N(2), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_WEEK_N(3), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_WEEK_N(4), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_WEEK_N(5), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    /* ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_MONTH_N (0 to 13) */
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_MONTH_N(0), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_MONTH_N(1), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_MONTH_N(2), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_MONTH_N(3), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_MONTH_N(4), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_MONTH_N(5), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_MONTH_N(6), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_MONTH_N(7), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_MONTH_N(8), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_MONTH_N(9), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_MONTH_N(10), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_MONTH_N(11), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_MONTH_N(12), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
    {
        ZCL_PREPAY_SVR_ATTR_COSTCON_DELIV_MONTH_N(13), ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_PREPAY_ATTR_FLAGS, 0, ZCL_PREPAY_ATTR_CALLBACK, {0, 0},
        {ZCL_PREPAY_ATTR_REPORT_INTVL_MIN, ZCL_PREPAY_ATTR_REPORT_INTVL_MAX}
    },
};
