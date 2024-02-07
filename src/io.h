#ifndef PINATABOARD_IO_H
#define PINATABOARD_IO_H

void readByteFromInputBuffer(uint8_t *ch, int* charIdx);
void get_bytes(uint32_t nbytes, uint8_t *ba);
void send_bytes(uint32_t nbytes, const uint8_t *ba);
void get_char(uint8_t *ch);
void send_char(uint8_t ch);
void readFromCharArray(uint8_t *ch);
void send_char_usb(uint8_t ch);
void get_char_usb(uint8_t *ch);
void send_bytes_usb(uint32_t nbytes, const uint8_t *ba);
void get_bytes_usb(uint32_t nbytes, uint8_t *ba);
void send_char_uart(uint8_t ch);
void get_char_uart(uint8_t *ch);
void send_bytes_uart(uint32_t nbytes, const uint8_t *ba);
void get_bytes_uart(uint32_t nbytes, uint8_t *ba);

#endif //PINATABOARD_IO_H
