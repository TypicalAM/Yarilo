import os
import RPi.GPIO as GPIO
import sys
from time import sleep, time
dirname = os.path.dirname(__file__)
sys.path.append(os.path.join(dirname, '..'))
from PIL import Image, ImageDraw, ImageFont
import spidev as SPI
from lib import LCD_2inch4
import client
import textwrap

# Constants
RST = 27
DC = 25
BL = 18
bus = 0
device = 0
fontsize = 25

BUTTON_PINS = {
    17: "ACCEPT",
    22: "REFUSE",
    26: "DOWN",
    13: "LEFT",
    6: "RIGHT",
    5: "UP"
}

stealth_mode = False

class Display:
    def __init__(self):
        self.disp = LCD_2inch4.LCD_2inch4(spi=SPI.SpiDev(bus, device), spi_freq=40000000, rst=RST, dc=DC, bl=BL)
        self.disp.Init()
        self.disp.command(0x36)
        self.disp.data(0x20)
        self.disp.clear()
        self.in_menu = False
        self.scrollable = False
        self.scroll_offset = 0
        self.horizontal_scroll_offset = 0
        self.current_message = None
        self.current_color = "BLACK"
        self.current_lines = []
        self.current_font = None
        self.battery_font = None
        self.current_y = 0
        self.current_text_height = 0
        self.battery_level = "Battery N/A"

    def update_battery_level(self):
        try:
            self.battery_level = f"{client.get_battery()}"
        except Exception as e:
            self.battery_level = "Battery N/A"
        self.refresh()

    def show_message(self, message, color="BLACK"):
        self.in_menu = False
        self.scrollable = False
        self.current_message = message
        self.current_color = color
        size = (320, 240)
        background = Image.new("RGB", size, (240, 255, 180))
        draw = ImageDraw.Draw(background)
        font = ImageFont.truetype(os.path.join(os.path.dirname(__file__), '../Font/Font02.ttf'), fontsize)
        self.current_font = font
        battery_font = ImageFont.truetype(os.path.join(os.path.dirname(__file__), '../Font/Font02.ttf'), fontsize - 5)
        self.battery_font = battery_font

        max_width = size[0]
        #wrapped_text = textwrap.fill(message, width=max_width // fontsize * 16)

        lines = message.split('\n')
        self.current_lines = lines
        text_height = len(lines) * fontsize
        self.current_text_height = text_height

        y = (size[1] - text_height) // 2 + 30
        self.current_y = y
        self.update_battery_level()

        #print(lines)

        if text_height > size[1] - 20:
            self.current_y = 30
            self.scrollable = True
            self.draw_text()
        else:
            self.scrollable = False
            y_offset = y
            for line in lines:
                draw.text((5, y_offset), line, fill=color, font=font)
                y_offset += fontsize
            draw.text((5, 5), self.battery_level, fill="BLACK", font=battery_font)
            self.disp.ShowImage(background.rotate(180))

    def draw_text(self):
        size = (320, 240)
        background = Image.new("RGB", size, (240, 255, 180))
        draw = ImageDraw.Draw(background)
        y_offset = self.current_y - self.scroll_offset
        x_offset = 5 + self.horizontal_scroll_offset
        for line in self.current_lines:
            draw.text((x_offset, y_offset), line, fill=self.current_color, font=self.current_font)
            y_offset += fontsize
        draw.text((5, 5), self.battery_level, fill="BLACK", font=self.battery_font)
        self.disp.ShowImage(background.rotate(180))

    def refresh(self):
        if self.current_message:
            self.draw_text()

    def show_list(self, items, selected_index):
        self.in_menu = True
        size = (320, 240)
        background = Image.new("RGB", size, (240, 255, 180))
        draw = ImageDraw.Draw(background)
        font = ImageFont.truetype(os.path.join(os.path.dirname(__file__), '../Font/Font02.ttf'), fontsize)

        for i, item in enumerate(items):
            color = "RED" if i == selected_index else "BLACK"
            draw.text((10, 30 + i * 30), item, fill=color, font=font)
        draw.text((5, 5), self.battery_level, fill="BLACK", font=self.battery_font)
        self.disp.ShowImage(background.rotate(180))
    
    def clear(self):
        self.disp.reset()
        self.disp.clear()


class ListMenu:
    def __init__(self, display):
        self.display = display
        self.stealth_text = "Stealth mode (OFF)"
        if stealth_mode:
            self.stealth_text = "Stealth mode (ON)"
        else:
            self.stealth_text = "Stealth mode (OFF)"
        self.items = ["Get sniffer list", "Get access point list", "Create recording", "Get battery", self.stealth_text, "Exit"]
        self.selected_index = 0

    def navigate(self, direction="NONE"):
        if direction == "UP":
            self.selected_index = (self.selected_index - 1) % len(self.items)
            sleep(0.1)
        elif direction == "DOWN":
            self.selected_index = (self.selected_index + 1) % len(self.items)
            sleep(0.1)
        elif direction == "NONE":
            self.selected_index = self.selected_index
            sleep(0.1)
        self.display.show_list(self.items, self.selected_index)

    def select(self):
        selected_item = self.items[self.selected_index]
        return selected_item

    def refuse(self):
        self.display.show_message("Action Refused!")


class ButtonHandler:
    def __init__(self, menu, display):
        self.menu = menu
        self.display = display
        GPIO.setmode(GPIO.BCM)
        for pin in BUTTON_PINS.keys():
            GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)

    def listen(self):
        while True:
            for pin, action in BUTTON_PINS.items():
                if GPIO.input(pin) == GPIO.HIGH:
                    if action in ["UP", "DOWN"] and display.in_menu == True:
                        self.menu.navigate(action)
                    elif action in ["UP", "DOWN"] and display.scrollable == True:
                        if action == "UP" and self.display.scroll_offset > 0:
                            self.display.scroll_offset -= 20
                            self.display.refresh()
                        elif action == "DOWN" and self.display.scroll_offset < self.display.current_text_height - 240:
                            self.display.scroll_offset += 20
                            self.display.refresh()
                    elif action == "LEFT" and not display.in_menu and self.display.horizontal_scroll_offset > 0:
                        self.display.horizontal_scroll_offset += 20
                        self.display.refresh()
                    elif action == "RIGHT" and not display.in_menu and self.display.horizontal_scroll_offset < self.display.current_font.getsize(self.display.current_message)[0] - 320:
                        self.display.horizontal_scroll_offset -= 20
                        self.display.refresh()
                    elif action == "ACCEPT":
                        selected = self.menu.select()
                        if selected == "Get sniffer list":
                            self.display.show_message(client.get_sniffer_list())
                        elif selected == "Get access point list":
                            self.display.show_message(client.get_access_point_list())
                        elif selected == "Create recording":
                            self.display.show_message(client.create_recording())
                        elif selected == "Get battery":
                            self.display.show_message(client.get_battery())
                        elif selected == "Stealth mode" and stealth_mode == False:
                            os.system("systemctl stop hostapd")
                            self.display.show_message("Stealth mode ENABLED!", "GREEN")
                        elif selected == "Stealth mode" and stealth_mode == True:
                            os.system("systemctl start hostapd")
                            self.display.show_message("Stealth mode DISABLED!", "GREEN")
                        elif selected == "Exit":
                            self.cleanup()
                            return
                    elif action == "REFUSE" and display.in_menu == False:
                        self.menu.navigate("NONE")
                        display.scroll_offset = 0

    def cleanup(self):
        display.clear()
        sys.exit(status=-1)

if __name__ == "__main__":
    try:
        display = Display()
        menu = ListMenu(display)
        button_handler = ButtonHandler(menu, display)
        client = client.Client()
        if not client.is_connected():
            display.show_message("Failed to connect to server!", "RED")
            sleep(3)
            display.clear()
            sys.exit()
        else:
            display.show_message("Connected to sniffer!", "GREEN")
            sleep(2)
        menu.navigate()
        button_handler.listen()
    except KeyboardInterrupt:
        GPIO.cleanup()
        sys.exit()
    except RuntimeError as e:
        print(f"Runtime error: {e}")
        GPIO.cleanup()
        sys.exit()
