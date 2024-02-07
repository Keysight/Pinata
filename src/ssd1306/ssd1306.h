#ifndef __SSD1306_H
#define __SSD1306_H

//Pin redefinitions for SSD1306 OLED screen
#define SPI_PORT GPIOB
#define GPIO_PORT GPIOF
#define OLED_SCK GPIO_Pin_13
#define OLED_MOSI GPIO_Pin_15
#define OLED_SS GPIO_Pin_4
#define OLED_DATACMD GPIO_Pin_5
#define OLED_RESET GPIO_Pin_8
//PB13 = SCK == blue wire to SSD1306 OLED display
//PB14 = MISO == nc
//PB15 = MOSI == green wire to SSD1306 OLED display
//PF4  = SS == white wire to SSD1306 OLED display
//PF5 = data/cmd# line of SSD1306 OLED display
//PF8 = reset line of SSD1306 OLED display

//Exported functions
void oled_reset(void);
void enable_OLEDdata_SPI(void);
void disable_OLEDdata_SPI(void);
void send_OLEDdata_SPI(uint8_t data);
void send_OLEDcmd_SPI(uint8_t data);
void oled_sendchars(int nchars, const char *str);
void oled_sendchar(const char c);
void sleep_ms(int nticks);
void oled_clear();


#define SSD1306_SETCONTRAST 0x81
#define SSD1306_DISPLAYALLON_RESUME 0xA4
#define SSD1306_DISPLAYALLON 0xA5
#define SSD1306_NORMALDISPLAY 0xA6
#define SSD1306_INVERTDISPLAY 0xA7
#define SSD1306_DISPLAYOFF 0xAE
#define SSD1306_DISPLAYON 0xAF

#define SSD1306_SETDISPLAYOFFSET 0xD3
#define SSD1306_SETCOMPINS 0xDA

#define SSD1306_SETVCOMDETECT 0xDB

#define SSD1306_SETDISPLAYCLOCKDIV 0xD5
#define SSD1306_SETPRECHARGE 0xD9

#define SSD1306_SETMULTIPLEX 0xA8

#define SSD1306_SETLOWCOLUMN 0x00
#define SSD1306_SETHIGHCOLUMN 0x10

#define SSD1306_SETSTARTLINE 0x40

#define SSD1306_MEMORYMODE 0x20
#define SSD1306_COLUMNADDR 0x21
#define SSD1306_PAGEADDR   0x22

#define SSD1306_COMSCANINC 0xC0
#define SSD1306_COMSCANDEC 0xC8

#define SSD1306_SEGREMAP 0xA0

#define SSD1306_CHARGEPUMP 0x8D

#define SSD1306_EXTERNALVCC 0x1
#define SSD1306_SWITCHCAPVCC 0x2

// Scrolling #defines
#define SSD1306_ACTIVATE_SCROLL 0x2F
#define SSD1306_DEACTIVATE_SCROLL 0x2E
#define SSD1306_SET_VERTICAL_SCROLL_AREA 0xA3
#define SSD1306_RIGHT_HORIZONTAL_SCROLL 0x26
#define SSD1306_LEFT_HORIZONTAL_SCROLL 0x27
#define SSD1306_VERTICAL_AND_RIGHT_HORIZONTAL_SCROLL 0x29
#define SSD1306_VERTICAL_AND_LEFT_HORIZONTAL_SCROLL 0x2A

#endif
