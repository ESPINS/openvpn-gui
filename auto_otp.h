#pragma once

#define AES_KEY_LENGTH 32

#define ERROR_AUTO_OTP -1L
#define ERROR_AUTO_OTP_ENC_KEY_EMPTY -2L
#define ERROR_AUTO_OTP_INCORRECT_PASSWORD -3L

INT_PTR CALLBACK AutoOtpSettingsDialogFunc(HWND, UINT, WPARAM, LPARAM);

void LoadAutoOtpSettings(HWND);

void SaveAutoOtpSettings(HWND);

void EncryptAutoOTPKey(HWND);

void DecryptAutoOTPKey(HWND);

void GenerateAutoOTPNumberTest(HWND);

LSTATUS GenerateAutoOTPNumber(unsigned char* otp_password, unsigned char* otp_number);

void GetAutoOTPRegistrySettings();