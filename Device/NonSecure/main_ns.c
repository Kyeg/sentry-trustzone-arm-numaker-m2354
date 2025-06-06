#include "NuMicro.h"
#include <arm_cmse.h>
#include <stdio.h>
#include <stdlib.h>

#define BLE

#ifdef BLE
#define RXBUFSIZE 20
// BLE Global variables
char *received_msg;
volatile int read_flag = 1;
// static volatile uint32_t g_u32comRbytes = 0;
// static volatile uint32_t g_u32comRhead = 0;
volatile uint32_t g_u32comRtail = 0;
#endif

typedef int32_t (*funcptr)(uint32_t);

void Timer_Start(void);

extern int32_t Secure_Free(int32_t (*)(int));
extern int32_t Secure_receive(char *msg);
extern int32_t Secure_func(char *msg);
extern int32_t Secure_BLE_callback(int32_t (*)(char));
void App_Init(uint32_t u32BootBase);
void DEBUG_PORT_Init(void);
void BLE_SendCommand(const char *cmd);
void BLE_SendMessage(char msg);
void BLE_Init(void);
void UART1_Interrupt_Disable(void);
void UART1_Interrupt_Enable(void);
// void UART1_IRQHandler(void);
int32_t NonSecure_BLE_send(char msg);
int32_t FreeMSG(int ticket);

void UART1_IRQHandler(void)
{
    // printf("\nUART1_IRQHandler was called\n");

    uint8_t u8InChar = 0xFF;
    /* Rx Ready or Time-out INT */
    if (UART_GET_INT_FLAG(UART1,
                          UART_INTSTS_RDAINT_Msk | UART_INTSTS_RXTOINT_Msk))
    {
        /* Read data until RX FIFO is empty */
        while (UART_GET_RX_EMPTY(UART1) == 0 && read_flag)
        {
            u8InChar = (uint8_t)UART_READ(UART1);
            // BLE_SendMessage(u8InChar);

            /* If the g_i32Pointer less than the length of ticket, the
            receive
               data is probably the part of ticket. Or it is part of large
               amount of data.  */
            if (received_msg == NULL)
            {
                // printf("received_msg is NULL\n");
                return;
            }
            else if (u8InChar == '$')
            {
                read_flag = 0;
                received_msg[g_u32comRtail] = '\0';
                // printf("\nReceived message from agent: %s\n", received_msg);
                break;
            }

            if (g_u32comRtail < 1000)
            {
                received_msg[g_u32comRtail] = u8InChar;
                g_u32comRtail++;
                // g_u32comRbytes++;

                received_msg[g_u32comRtail] = '\0';
            }
        }
    }

    if (UART1->FIFOSTS & (UART_FIFOSTS_BIF_Msk | UART_FIFOSTS_FEF_Msk |
                          UART_FIFOSTS_PEF_Msk | UART_FIFOSTS_RXOVIF_Msk))
    {
        UART1->FIFOSTS = (UART_FIFOSTS_BIF_Msk | UART_FIFOSTS_FEF_Msk |
                          UART_FIFOSTS_PEF_Msk | UART_FIFOSTS_RXOVIF_Msk);
    }
}

int ReceiveMessage(char *buffer, int bufferSize)
{
    int index = 0;
    while (index < bufferSize - 1)
    {
        if (UART_IS_RX_READY(UART0))
        {
            char receivedChar = UART_READ(UART0);
            if (receivedChar == '$')
            {
                break;
            }
            buffer[index++] = receivedChar;
        }
    }
    buffer[index] = '\0'; // 確保字符串結束
    return index > 0;
}

/*----------------------------------------------------------------------------
  Main function
 *----------------------------------------------------------------------------*/
int main(void)
{
    DEBUG_PORT_Init();
    UART_Open(UART1, 9600);
    UART_EnableFlowCtrl(UART1);

    /* Set RTS Trigger Level as 8 bytes */
    UART1->FIFO =
        (UART1->FIFO & (~UART_FIFO_RTSTRGLV_Msk)) | UART_FIFO_RTSTRGLV_8BYTES;

    /* Set RX Trigger Level as 8 bytes */
    UART1->FIFO =
        (UART1->FIFO & (~UART_FIFO_RFITL_Msk)) | UART_FIFO_RFITL_8BYTES;

    /* Set Timeout time 0x3E bit-time and time-out counter enable */
    UART_SetTimeoutCnt(UART1, 0x3E);
    UART1_Interrupt_Enable();
    BLE_Init();

    Secure_BLE_callback(&NonSecure_BLE_send);
    Secure_Free(&FreeMSG);

    // printf("\n");
    // printf("+---------------------------------------------+\n");
    // printf("|           Nonsecure is running ...          |\n");
    // printf("+---------------------------------------------+\n");

    // BLE_SendMessage("Hello from M2354!\r\n");
    received_msg = (char *)malloc(1000 * sizeof(char));

    // printf("Non-secure code is running\n");

    while (1)
    {
        ReceiveMessage(received_msg, 1000);
        // BLE_SendCommand(received_msg);

        Timer_Start();
        Secure_receive(received_msg);

        if (received_msg == NULL)
        {
            BLE_SendCommand("The message is NULL");
            received_msg = (char *)malloc(1000 * sizeof(char));
        }
        else
        {
            BLE_SendCommand("Hello from M2354!");
        }
    }
}

void DEBUG_PORT_Init(void)
{
    /*---------------------------------------------------------------------------------------------------------*/
    /* Init UART */
    /*---------------------------------------------------------------------------------------------------------*/

    DEBUG_PORT->BAUD =
        UART_BAUD_MODE2 | UART_BAUD_MODE2_DIVIDER(__HIRC, 115200);
    DEBUG_PORT->LINE = UART_WORD_LEN_8 | UART_PARITY_NONE | UART_STOP_BIT_1;
}

void App_Init(uint32_t u32BootBase)
{
    funcptr fp;
    uint32_t u32StackBase;

    /* 2nd entry contains the address of the Reset_Handler (CMSIS-CORE) function
     */
    fp = ((funcptr)(*(((uint32_t *)SCB->VTOR) + 1)));

    /* Check if the stack is in secure SRAM space */
    u32StackBase = M32(u32BootBase);
    if ((u32StackBase >= 0x30000000UL) && (u32StackBase < 0x40000000UL))
    {
        // printf("Execute non-secure code ...\n");
        /* SCB.VTOR points to the target Secure vector table base address. */
        SCB->VTOR = u32BootBase;

        fp(0); /* Non-secure function call */
    }
    else
    {
        /* Something went wrong */
        // printf("No code in non-secure region!\n");

        while (1)
            ;
    }
}

#ifdef BLE
void BLE_SendCommand(const char *cmd)
{
    // printf("\nSending command: %s\n", cmd);

    int i = 0;
    while (cmd[i] != '\0')
    {
        UART_WRITE(UART1, cmd[i]);
        while (UART_IS_TX_FULL(UART1))
            ;
        i++;
    }

    UART_WRITE(UART1, '\r');
    while (UART_IS_TX_FULL(UART1))
        ;
    UART_WRITE(UART1, '\n');
    while (UART_IS_TX_FULL(UART1))
        ;

    CLK_SysTickDelay(500000);
}

int32_t NonSecure_BLE_send(char msg)
{
    BLE_SendMessage(msg);
    return 1;
}

int32_t FreeMSG(int ticket)
{
    if (ticket == -1)
    {
        BLE_SendCommand("Ticket is permissionless");
    }
    else if (ticket == -2)
    {
        BLE_SendCommand("Something went wrong");
    }
    if (received_msg != NULL)
    {
        free(received_msg);
        received_msg = NULL;
        BLE_SendCommand("Memory freed");
    }
    return 1;
}

// Simple function to send a message
void BLE_SendMessage(char msg)
{
    // printf("%c", msg);
    //  printf("\nSending message: %s", msg);

    // int i = 0;
    // while (msg[i] != '\0') {
    UART_WRITE(UART1, msg);
    while (UART_IS_TX_FULL(UART1))
        ;
    //     i++;
    // }
}

void BLE_Init(void)
{
    // printf("\nInitializing BLE module...\n");

    CLK_SysTickDelay(1000000);

    // Basic AT test
    BLE_SendCommand("AT");

    // Set slave mode
    BLE_SendCommand("AT+ROLE0");

    // Start module
    BLE_SendCommand("AT+START");

    // printf("BLE initialization completed\n");
}

void UART1_Interrupt_Disable(void)
{
    /* Disable RDA and RTO Interrupt */
    NVIC_DisableIRQ(UART1_IRQn);
    UART_DisableInt(UART1, (UART_INTEN_RDAIEN_Msk | UART_INTEN_RLSIEN_Msk |
                            UART_INTEN_RXTOIEN_Msk));
}

void UART1_Interrupt_Enable(void)
{
    /* Enable RDA and RTO Interrupt */
    UART_EnableInt(UART1, (UART_INTEN_RDAIEN_Msk | UART_INTEN_RLSIEN_Msk |
                           UART_INTEN_RXTOIEN_Msk));
    NVIC_EnableIRQ(UART1_IRQn);
}

void Timer_Start(void)
{

    TIMER_Open(TIMER2, TIMER_PERIODIC_MODE, 10000);

    TIMER_SET_PRESCALE_VALUE(TIMER2, 31);

    TIMER_SET_CMP_VALUE(TIMER2, 0xFFFFFF);

    TIMER_ResetCounter(TIMER2);

    TIMER_Start(TIMER2);

    // printf("\nTimer started!!!");
}
#endif
