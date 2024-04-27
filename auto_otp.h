#pragma once

#define AES_KEY_LENGTH 32

#define ERROR_AUTO_OTP -1L
#define ERROR_AUTO_OTP_ENC_KEY_EMPTY -2L
#define ERROR_AUTO_OTP_INCORRECT_PASSWORD -3L

#define NTP_SERVER "time.windows.com"
#define NTP_PORT "123"
#define NTP_PACKET_SIZE 48
#define NTP_TIMESTAMP_DELTA 2208988800ull
#define NTP_TIMEOUT_SEC 5

typedef struct {
    UINT8 li_vn_mode;
    UINT8 stratum;
    UINT8 poll;
    UINT8 precision;
    UINT32 rootDelay;
    UINT32 rootDispersion;
    UINT32 refId;
    UINT32 refTm_s;
    UINT32 refTm_f;
    UINT32 origTm_s;
    UINT32 origTm_f;
    UINT32 rxTm_s;
    UINT32 rxTm_f;
    UINT32 txTm_s;
    UINT32 txTm_f;
} ntp_packet;

INT_PTR CALLBACK AutoOtpSettingsDialogFunc(HWND, UINT, WPARAM, LPARAM);

void LoadAutoOtpSettings(HWND);

void SaveAutoOtpSettings(HWND);

void EncryptAutoOTPKey(HWND);

void DecryptAutoOTPKey(HWND);

void GenerateAutoOTPNumberTest(HWND);

LSTATUS GenerateAutoOTPNumber(unsigned char* otp_password, unsigned char* otp_number);

void GetAutoOTPRegistrySettings();