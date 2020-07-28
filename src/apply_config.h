#ifndef __APPLY_CONFIG_H
#define __APPLY_CONFIG_H

#include "config.h"

#include "pppoe_common.h"
#include "ipaddr_learner.h"


enum LedCtrlTypeEnum {
    LedCtrlTypeStart,
    LedCtrlTypeOk,
    LedCtrlTypeFailed,
    LedCtrlTypeOver,
};

/* learn state type */
typedef enum {
    learnStateInit = 0,
    learnStateLearning,
    learnStateTimeout,
    learnStateFailed,
    learnStateSucceed,
} LearnState_t;


int g_apply_probe_config;
unsigned int g_update_idx;


int ledControl(enum LedCtrlTypeEnum ctrlType);

void resetInterfacePhy(void);

int setCfgLearnState(LearnState_t state);

int applyProbeNetConfig(int is_timeout);

#endif
