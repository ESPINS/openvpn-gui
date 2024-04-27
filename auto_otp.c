#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <windows.h>
#include <windowsx.h>
#include <prsht.h>
#include <tchar.h>
#include <winhttp.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sysinfoapi.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>
#include <math.h>

#include "main.h"
#include "options.h"
#include "registry.h"
#include "auto_otp.h"
#include "openvpn-gui-res.h"
#include "localization.h"
#include "manage.h"
#include "openvpn.h"
#include "misc.h"
#include "cotp.h"

extern options_t o;

static const int32_t SHA1_BYTES   = 160 / 8;	// 20
static const int32_t SHA256_BYTES = 256 / 8;	// 32
static const int32_t SHA512_BYTES = 512 / 8;	// 64

// byte_secret is unbase32 key
// byte_string is data to be HMAC'd
// returns 0 for failure otherwise the length of the string
int hmac_algo_sha1(const char *byte_secret, int byte_secret_len, const char *byte_string, char *out)
{
    // Output len
    unsigned int len = SHA1_BYTES;

    unsigned char *result = HMAC(
        EVP_sha1(),                                    // algorithm
        (unsigned char *)byte_secret, byte_secret_len, // key
        (unsigned char *)byte_string, 8,               // data
        (unsigned char *)out,                          // output
        &len                                           // output length
    );

    // Return the HMAC success
    return result == 0 ? 0 : len;
}

int hmac_algo_sha256(const char *byte_secret, int byte_secret_len, const char *byte_string, char *out)
{
    // Output len
    unsigned int len = SHA256_BYTES;

    unsigned char *result = HMAC(
        EVP_sha256(),                                  // algorithm
        (unsigned char *)byte_secret, byte_secret_len, // key
        (unsigned char *)byte_string, 8,               // data
        (unsigned char *)out,                          // output
        &len                                           // output length
    );

    // Return the HMAC success
    return result == 0 ? 0 : len;
}

int hmac_algo_sha512(const char *byte_secret, int byte_secret_len, const char *byte_string, char *out)
{
    // Output len
    unsigned int len = SHA512_BYTES;

    unsigned char *result = HMAC(
        EVP_sha512(),                                  // algorithm
        (unsigned char *)byte_secret, byte_secret_len, // key
        (unsigned char *)byte_string, 8,               // data
        (unsigned char *)out,                          // output
        &len                                           // output length
    );

    // Return the HMAC success
    return result == 0 ? 0 : len;
}

uint64_t get_current_time()
{
    uint64_t milliseconds = 0;

    FILETIME fileTime;
    GetSystemTimeAsFileTime(&fileTime);

    ULARGE_INTEGER largeInteger;
    largeInteger.LowPart = fileTime.dwLowDateTime;
    largeInteger.HighPart = fileTime.dwHighDateTime;

    milliseconds = (largeInteger.QuadPart - 116444736000000000ULL) / 10000000ULL;

    return milliseconds;
}

int max_base64_encode_length(int length)
{
    return ((length * 4 + 2) / 3) + 10;
}

int max_base64_decode_length(int length)
{
    return ((length * 3) / 4) + 10;
}

void base64_encode(const unsigned char *input, int length, unsigned char *out, int *out_len)
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(bio, input, length);
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bufferPtr);
    memcpy(out, bufferPtr->data, bufferPtr->length);
    *out_len = bufferPtr->length;

    BIO_free_all(bio);
}

void base64_decode(const unsigned char *input, int length, unsigned char *out, int *out_len)
{
    BIO *bio, *b64;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input, length);
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    int decoded_len = BIO_read(bio, out, length);

    *out_len = decoded_len;

    BIO_free_all(bio);
}

LSTATUS encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, unsigned char *ciphertext, int *ciphertext_len)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int encrypt_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return ERROR_AUTO_OTP;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL))
        return ERROR_AUTO_OTP;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return ERROR_AUTO_OTP;

    encrypt_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return ERROR_AUTO_OTP;

    encrypt_len += len;

    EVP_CIPHER_CTX_free(ctx);

    *ciphertext_len = encrypt_len;

    return ERROR_SUCCESS;
}

LSTATUS decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, unsigned char *plaintext, int *plaintext_len)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int decrypt_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return ERROR_AUTO_OTP;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL))
        return ERROR_AUTO_OTP;

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return ERROR_AUTO_OTP;

    decrypt_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        return ERROR_AUTO_OTP;

    decrypt_len += len;

    EVP_CIPHER_CTX_free(ctx);

    *plaintext_len = decrypt_len;

    return ERROR_SUCCESS;
}

INT_PTR CALLBACK
AutoOtpSettingsDialogFunc(HWND hwndDlg, UINT msg, WPARAM wParam, UNUSED LPARAM lParam)
{
    HICON hIcon;
    LPPSHNOTIFY psn;

    switch (msg)
    {
    case WM_INITDIALOG:
        hIcon = LoadLocalizedIcon(ID_ICO_APP);
        if (hIcon)
        {
            SendMessage(hwndDlg, WM_SETICON, (WPARAM)(ICON_SMALL), (LPARAM)(hIcon));
            SendMessage(hwndDlg, WM_SETICON, (WPARAM)(ICON_BIG), (LPARAM)(hIcon));
        }

        SendMessage(GetDlgItem(hwndDlg, ID_EDT_OTP_KEY), EM_SETLIMITTEXT, 500, 0);
        SendMessage(GetDlgItem(hwndDlg, ID_EDT_CREATE_PASSWORD), EM_SETLIMITTEXT, 30, 0);
        SendMessage(GetDlgItem(hwndDlg, ID_EDT_CONFIRM_PASSWORD), EM_SETLIMITTEXT, 30, 0);

        LoadAutoOtpSettings(hwndDlg);
        break;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case ID_BTN_GEN_NUMBER:
            if (HIWORD(wParam) == BN_CLICKED)
            {
                GenerateAutoOTPNumberTest(hwndDlg);
            }
            break;

        case ID_BTN_GEN_KEY:
            if (HIWORD(wParam) == BN_CLICKED)
            {
                EncryptAutoOTPKey(hwndDlg);
            }
            break;

        case ID_BTN_KEY_LOAD:
            if (HIWORD(wParam) == BN_CLICKED)
            {
                DecryptAutoOTPKey(hwndDlg);
            }
            break;
        }
        break;

    case WM_NOTIFY:
        psn = (LPPSHNOTIFY)lParam;
        if (psn->hdr.code == (UINT)PSN_KILLACTIVE)
        {
            SetWindowLongPtr(hwndDlg, DWLP_MSGRESULT, FALSE);
            return TRUE;
        }
        else if (psn->hdr.code == (UINT)PSN_APPLY)
        {
            SaveAutoOtpSettings(hwndDlg);
            SetWindowLongPtr(hwndDlg, DWLP_MSGRESULT, PSNRET_NOERROR);
            return TRUE;
        }
        break;

    case WM_CLOSE:
        EndDialog(hwndDlg, LOWORD(wParam));
        return TRUE;
    }
    return FALSE;
}

void
LoadAutoOtpSettings(HWND hwndDlg)
{
    /* Set OTP Time Settings */
    if (o.otp_time == otp_time30)
    {
        SendMessage(GetDlgItem(hwndDlg, ID_RB_OTP_30SEC), BM_CLICK, 0, 0);
    }
    else if (o.otp_time == otp_time60)
    {
        SendMessage(GetDlgItem(hwndDlg, ID_RB_OTP_60SEC), BM_CLICK, 0, 0);
    }

    /* Set OTP Digit Settings */
    if (o.otp_digit == otp_digit6)
    {
        SendMessage(GetDlgItem(hwndDlg, ID_RB_OTP_6DIGIT), BM_CLICK, 0, 0);
    }
    else if (o.otp_digit == otp_digit8)
    {
        SendMessage(GetDlgItem(hwndDlg, ID_RB_OTP_8DIGIT), BM_CLICK, 0, 0);
    }

    /* Set OTP HashMode Settings */
    if (o.otp_hash_mode == otp_sha1)
    {
        SendMessage(GetDlgItem(hwndDlg, ID_RB_OTP_SHA1), BM_CLICK, 0, 0);
    }
    else if (o.otp_hash_mode == otp_sha256)
    {
        SendMessage(GetDlgItem(hwndDlg, ID_RB_OTP_SHA256), BM_CLICK, 0, 0);
    }
    else if (o.otp_hash_mode == otp_sha512)
    {
        SendMessage(GetDlgItem(hwndDlg, ID_RB_OTP_SHA512), BM_CLICK, 0, 0);
    }

    int wLength = MultiByteToWideChar(CP_UTF8, 0, (char *)o.otp_enc_key, -1, NULL, 0);
    TCHAR otp_enc_key[wLength + 1];
    memset(otp_enc_key, L'\0', wLength + 1);
    MultiByteToWideChar(CP_UTF8, 0, (char *)o.otp_enc_key, -1, otp_enc_key, wLength);

    HWND hWnd_label_text = GetDlgItem(hwndDlg, ID_TXT_GEN_KEY);

    if (_tcslen(otp_enc_key) == 0)
    {
        SendMessage(hWnd_label_text, WM_SETTEXT, 0, (LPARAM) _T("Encrypted Key : Not Set"));
    }
    else
    {
        SendMessage(hWnd_label_text, WM_SETTEXT, 0, (LPARAM) _T("Encrypted Key : Applied"));
    }
}

void
SaveAutoOtpSettings(HWND hwndDlg)
{
    HKEY regkey;
    DWORD dwDispos;
    TCHAR otp_time_string[2] = _T("0");
    TCHAR otp_digit_string[2] = _T("0");
    TCHAR otp_hash_mode_string[2] = _T("1");
    TCHAR otp_subkey[MAX_PATH];

    /* Save OTP Time Settings */
    if (IsDlgButtonChecked(hwndDlg, ID_RB_OTP_30SEC) == BST_CHECKED)
    {
        o.otp_time = otp_time30;
        otp_time_string[0] = _T('0');
    }
    else if (IsDlgButtonChecked(hwndDlg, ID_RB_OTP_60SEC) == BST_CHECKED)
    {
        o.otp_time = otp_time60;
        otp_time_string[0] = _T('1');
    }

    /* Save OTP Digit Settings */
    if (IsDlgButtonChecked(hwndDlg, ID_RB_OTP_6DIGIT) == BST_CHECKED)
    {
        o.otp_digit = otp_digit6;
        otp_digit_string[0] = _T('0');
    }
    else if (IsDlgButtonChecked(hwndDlg, ID_RB_OTP_8DIGIT) == BST_CHECKED)
    {
        o.otp_digit = otp_digit8;
        otp_digit_string[0] = _T('1');
    }

    /* Save OTP HashMode Settings */
    if (IsDlgButtonChecked(hwndDlg, ID_RB_OTP_SHA1) == BST_CHECKED)
    {
        o.otp_hash_mode = otp_sha1;
        otp_hash_mode_string[0] = _T('0');
    }
    else if (IsDlgButtonChecked(hwndDlg, ID_RB_OTP_SHA256) == BST_CHECKED)
    {
        o.otp_hash_mode = otp_sha256;
        otp_hash_mode_string[0] = _T('1');
    }
    else if (IsDlgButtonChecked(hwndDlg, ID_RB_OTP_SHA512) == BST_CHECKED)
    {
        o.otp_hash_mode = otp_sha512;
        otp_hash_mode_string[0] = _T('2');
    }

    int wLength = MultiByteToWideChar(CP_UTF8, 0, (char *)o.otp_enc_key, -1, NULL, 0);
    TCHAR otp_enc_key[wLength + 1];
    memset(otp_enc_key, L'\0', wLength + 1);
    MultiByteToWideChar(CP_UTF8, 0, (char *)o.otp_enc_key, -1, otp_enc_key, wLength);

    /* Open Registry for writing */
    _sntprintf_0(otp_subkey, _T("%ls\\otp"), GUI_REGKEY_HKCU);
    if (RegCreateKeyEx(HKEY_CURRENT_USER, otp_subkey, 0, _T(""), REG_OPTION_NON_VOLATILE,
                       KEY_WRITE, NULL, &regkey, &dwDispos) != ERROR_SUCCESS)
    {
        /* error creating Registry-Key */
        ShowLocalizedMsg(IDS_ERR_CREATE_REG_HKCU_KEY, otp_subkey);
        return;
    }

    /* Save Settings to registry */
    SetRegistryValue(regkey, _T("otp_time"), otp_time_string);
    SetRegistryValue(regkey, _T("otp_digit"), otp_digit_string);
    SetRegistryValue(regkey, _T("otp_hash_mode"), otp_hash_mode_string);
    SetRegistryValue(regkey, _T("otp_enc_key"), otp_enc_key);

    RegCloseKey(regkey);
}

void
EncryptAutoOTPKey(HWND hwndDlg)
{
    TCHAR otp_key_w[500 + 1];
    TCHAR create_password_w[30 + 1];
    TCHAR confirm_password_w[30 + 1];

    GetDlgItemText(hwndDlg, ID_EDT_OTP_KEY, otp_key_w, _countof(otp_key_w));
    GetDlgItemText(hwndDlg, ID_EDT_CREATE_PASSWORD, create_password_w, _countof(create_password_w));
    GetDlgItemText(hwndDlg, ID_EDT_CONFIRM_PASSWORD, confirm_password_w, _countof(confirm_password_w));

    if (_tcslen(otp_key_w) == 0)
    {
        MessageBox(hwndDlg, L"You must enter the OTP Key.", L"Error", MB_OK);
        return;
    }

    if (_tcslen(create_password_w) == 0 || _tcslen(create_password_w) == 0)
    {
        MessageBox(hwndDlg, L"You must enter the Password.", L"Error", MB_OK);
        return;
    }

    if (_tcscmp(create_password_w, confirm_password_w) != 0)
    {
        MessageBox(hwndDlg, L"Passwords don't match. Please try again.", L"Error", MB_OK);
        return;
    }

    unsigned char otp_key[512 * 6];
    unsigned char password[AES_KEY_LENGTH];

    memset(otp_key, '\0', sizeof(otp_key));
    memset(password, '\0', sizeof(password));

    WideCharToMultiByte(CP_UTF8, 0, otp_key_w, -1, (char *)otp_key, sizeof(otp_key), NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, confirm_password_w, -1, (char *)password, AES_KEY_LENGTH, NULL, NULL);

    int otp_key_len = strlen((char *)otp_key);

    int block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());
    int max_ciphertext_len = block_size + (floor((double)otp_key_len / block_size) * block_size) + 10;

    unsigned char ciphertext[max_ciphertext_len];
    int ciphertext_len = 0;

    encrypt(otp_key, otp_key_len, password, ciphertext, &ciphertext_len);

    int base64_encodetext_len = 0;
    int max_base64_encode_len = max_base64_encode_length(ciphertext_len);
    unsigned char base64_encodetext[max_base64_encode_len];
    memset(base64_encodetext, '\0', max_base64_encode_len);

    base64_encode(ciphertext, ciphertext_len, base64_encodetext, &base64_encodetext_len);

    strcpy((char *)o.otp_enc_key, (const char *)base64_encodetext);

    HWND hWnd_label_text = GetDlgItem(hwndDlg, ID_TXT_GEN_KEY);
    SendMessage(hWnd_label_text, WM_SETTEXT, 0, (LPARAM) _T("Encrypted Key : Applied"));
}

void
DecryptAutoOTPKey(HWND hwndDlg)
{
    TCHAR create_password_w[30 + 1];
    TCHAR confirm_password_w[30 + 1];

    GetDlgItemText(hwndDlg, ID_EDT_CREATE_PASSWORD, create_password_w, _countof(create_password_w));
    GetDlgItemText(hwndDlg, ID_EDT_CONFIRM_PASSWORD, confirm_password_w, _countof(confirm_password_w));

    if (_tcslen(create_password_w) == 0 || _tcslen(create_password_w) == 0)
    {
        MessageBox(hwndDlg, L"You must enter the Password.", L"Error", MB_OK);
        return;
    }

    if (_tcscmp(create_password_w, confirm_password_w) != 0)
    {
        MessageBox(hwndDlg, L"Passwords don't match. Please try again.", L"Error", MB_OK);
        return;
    }

    unsigned char password[AES_KEY_LENGTH];
    memset(password, '\0', sizeof(password));
    WideCharToMultiByte(CP_UTF8, 0, confirm_password_w, -1, (char *)password, AES_KEY_LENGTH, NULL, NULL);

    int base64_encodetext_len = strlen((char *)o.otp_enc_key);

    int base64_decodetext_len = 0;
    int max_base64_decode_len = max_base64_decode_length(base64_encodetext_len);
    unsigned char base64_decodetext[max_base64_decode_len];

    base64_decode(o.otp_enc_key, base64_encodetext_len, base64_decodetext, &base64_decodetext_len);

    unsigned char otp_key[512 * 6];
    int otp_key_len = 0;
    memset(otp_key, '\0', sizeof(otp_key));

    LSTATUS result = decrypt(base64_decodetext, base64_decodetext_len, password, otp_key, &otp_key_len);

    if (result != ERROR_SUCCESS)
    {
        MessageBox(hwndDlg, L"Your password is incorrect.", L"Error", MB_OK);
        return;
    }

    int wLength = MultiByteToWideChar(CP_UTF8, 0, (char *)otp_key, -1, NULL, 0);
    TCHAR otp_key_w[wLength + 1];
    memset(otp_key_w, L'\0', wLength + 1);
    MultiByteToWideChar(CP_UTF8, 0, (char *)otp_key, -1, otp_key_w, wLength);

    HWND hEdit = GetDlgItem(hwndDlg, ID_EDT_OTP_KEY);
    SetWindowText(hEdit, otp_key_w);
}

void
GenerateAutoOTPNumberTest(HWND hwndDlg)
{
    TCHAR otp_key_w[500 + 1];
    GetDlgItemText(hwndDlg, ID_EDT_OTP_KEY, otp_key_w, _countof(otp_key_w));

    if (_tcslen(otp_key_w) == 0)
    {
        MessageBox(hwndDlg, L"You must enter the OTP Key.", L"Error", MB_OK);
        return;
    }

    unsigned char otp_key[512 * 6];
    memset(otp_key, '\0', sizeof(otp_key));
    WideCharToMultiByte(CP_UTF8, 0, otp_key_w, -1, (char *)otp_key, sizeof(otp_key), NULL, NULL);

    OTPData odata;
    memset(&odata, 0, sizeof(OTPData));

    COTP_ALGO algo;
    int interval = 30;
    int digits = 6;

    if (IsDlgButtonChecked(hwndDlg, ID_RB_OTP_30SEC) == BST_CHECKED)
    {
        interval = 30;
    }
    else
    {
        interval = 60;
    }

    if (IsDlgButtonChecked(hwndDlg, ID_RB_OTP_6DIGIT) == BST_CHECKED)
    {
        digits = 6;
    }
    else
    {
        digits = 8;
    }

    if (IsDlgButtonChecked(hwndDlg, ID_RB_OTP_SHA1) == BST_CHECKED)
    {
        algo = hmac_algo_sha1;
    }
    else if (IsDlgButtonChecked(hwndDlg, ID_RB_OTP_SHA256) == BST_CHECKED)
    {
        algo = hmac_algo_sha256;
    }
    else
    {
        algo = hmac_algo_sha512;
    }

    OTPData *tdata = totp_new(
        &odata,
        (const char *)otp_key,
        algo,
        get_current_time,
        (uint32_t)digits,
        (uint32_t)interval);

    char tcode[digits + 1];
    memset(tcode, '\0', digits + 1);

    int totp_err = totp_now(tdata, tcode);
    if (totp_err == OTP_ERROR)
    {
        MessageBox(hwndDlg, L"OTP number generation failure.", L"Error", MB_OK);
        return;
    }

    int wLength = MultiByteToWideChar(CP_UTF8, 0, tcode, -1, NULL, 0);
    TCHAR tcode_w[wLength + 1];
    memset(tcode_w, L'\0', wLength + 1);
    MultiByteToWideChar(CP_UTF8, 0, tcode, -1, tcode_w, wLength);

    MessageBox(hwndDlg, tcode_w, L"OTP Number", MB_OK);
}

LSTATUS
GenerateAutoOTPNumber(unsigned char* otp_password, unsigned char* otp_number)
{
    unsigned char password[AES_KEY_LENGTH];
    memset(password, '\0', sizeof(password));
    strcpy((char *)password, (const char *)otp_password);

    if (strlen((char *)o.otp_enc_key) == 0)
    {
        return ERROR_AUTO_OTP_ENC_KEY_EMPTY;
    }

    int base64_encodetext_len = strlen((char *)o.otp_enc_key);

    int base64_decodetext_len = 0;
    int max_base64_decode_len = max_base64_decode_length(base64_encodetext_len);
    unsigned char base64_decodetext[max_base64_decode_len];

    base64_decode(o.otp_enc_key, base64_encodetext_len, base64_decodetext, &base64_decodetext_len);

    unsigned char otp_key[512 * 6];
    int otp_key_len = 0;
    memset(otp_key, '\0', sizeof(otp_key));

    LSTATUS result = decrypt(base64_decodetext, base64_decodetext_len, password, otp_key, &otp_key_len);

    if (result != ERROR_SUCCESS)
    {
        return ERROR_AUTO_OTP_INCORRECT_PASSWORD;
    }

    OTPData odata;
    memset(&odata, 0, sizeof(OTPData));

    COTP_ALGO algo;
    int interval = 30;
    int digits = 6;

    if (o.otp_time == otp_time30)
    {
        interval = 30;
    }
    else
    {
        interval = 60;
    }

    if (o.otp_digit == otp_digit6)
    {
        digits = 6;
    }
    else
    {
        digits = 8;
    }

    if (o.otp_hash_mode == otp_sha1)
    {
        algo = hmac_algo_sha1;
    }
    else if (o.otp_hash_mode == otp_sha256)
    {
        algo = hmac_algo_sha256;
    }
    else
    {
        algo = hmac_algo_sha512;
    }

    OTPData *tdata = totp_new(
        &odata,
        (const char *)otp_key,
        algo,
        get_current_time,
        (uint32_t)digits,
        (uint32_t)interval);

    char tcode[digits + 1];
    memset(tcode, '\0', digits + 1);

    int totp_err = totp_now(tdata, tcode);
    if (totp_err == OTP_ERROR)
    {
        return ERROR_AUTO_OTP;
    }

    strcpy((char *)otp_number, (const char *)tcode);

    return ERROR_SUCCESS;
}

void
GetAutoOTPRegistrySettings()
{
    memset(o.otp_enc_key, '\0', sizeof(o.otp_enc_key));

    LONG status;
    HKEY regkey;
    TCHAR otp_time_string[2] = _T("0");
    TCHAR otp_digit_string[2] = _T("0");
    TCHAR otp_hash_mode_string[2] = _T("1");
    TCHAR otp_subkey[MAX_PATH];
    TCHAR otp_enc_key[4096];

    memset(otp_enc_key, L'\0', sizeof(otp_enc_key));

    /* Open Registry for reading */
    _sntprintf_0(otp_subkey, _T("%ls\\otp"), GUI_REGKEY_HKCU);
    status = RegOpenKeyEx(HKEY_CURRENT_USER, otp_subkey, 0, KEY_READ, &regkey);
    if (status == ERROR_SUCCESS)
    {
        /* get registry settings */
        GetRegistryValue(regkey, _T("otp_time"), otp_time_string, _countof(otp_time_string));
        GetRegistryValue(regkey, _T("otp_digit"), otp_digit_string, _countof(otp_digit_string));
        GetRegistryValue(regkey, _T("otp_hash_mode"), otp_hash_mode_string, _countof(otp_hash_mode_string));
        GetRegistryValue(regkey, _T("otp_enc_key"), otp_enc_key, _countof(otp_enc_key));
    }

    WideCharToMultiByte(CP_UTF8, 0, otp_enc_key, -1, (char *)o.otp_enc_key, sizeof(o.otp_enc_key), NULL, NULL);

    /* Set OTP Time Settings */
    if (otp_time_string[0] == _T('0'))
    {
        o.otp_time = otp_time30;
    }
    else if (otp_time_string[0] == _T('1'))
    {
        o.otp_time = otp_time60;
    }

    /* Set OTP Digit Settings */
    if (otp_digit_string[0] == _T('0'))
    {
        o.otp_digit = otp_digit6;
    }
    else if (otp_digit_string[0] == _T('1'))
    {
        o.otp_digit = otp_digit8;
    }

    /* Set OTP HashMode Settings */
    if (otp_hash_mode_string[0] == _T('0'))
    {
        o.otp_hash_mode = otp_sha1;
    }
    else if (otp_hash_mode_string[0] == _T('1'))
    {
        o.otp_hash_mode = otp_sha256;
    }
    else if (otp_hash_mode_string[0] == _T('2'))
    {
        o.otp_hash_mode = otp_sha512;
    }

    if (status == ERROR_SUCCESS)
    {
        RegCloseKey(regkey);
    }
}