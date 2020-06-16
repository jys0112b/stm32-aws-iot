#ifndef __GLOBAL_H
#define __GLOBAL_H

#include "main.h"
#include "stm32f4xx_hal.h"

typedef enum {FALSE2 = 0, TRUE2 = !FALSE2} bool;
#define true TRUE2
#define false FALSE2

typedef struct {
   volatile bool flg;
   uint8_t tCnt, t100ms, t500ms;
} TIM_User_InitTypeDef;

typedef struct {
   volatile bool rfg; // �����÷���
   volatile uint8_t tb[50],rb[50]; // �ۼ��Ź���
   volatile uint8_t rc,tc,tcMax; // ����, �۽�ī��Ʈ
   uint8_t high,low; // for modbus
   uint8_t rxTmr; // ����Ÿ�Ӿƿ�
} USART_User_InitTypeDef;

extern USART_User_InitTypeDef cm1;
extern TIM_User_InitTypeDef tim;
#endif

