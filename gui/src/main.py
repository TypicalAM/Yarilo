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
BUS = 0
DEVICE = 0
FONT_SIZE = 25

BUTTON_PINS = {
    17: "ACCEPT",
    22: "REFUSE",
    26: "DOWN",
    13: "LEFT",
    6: "RIGHT",
    5: "UP"
}

STEALTH_MODE = False

class Display:
    def __init__(self):
        self.disp = LCD_2inch4.LCD_2inch4(spi=SPI.SpiDev(BUS, DEVICE), spi_freq=40000000, rst=RST, dc=DC, bl=BL)
        self.disp.Init()
        self.disp.command(0x36)
        self.disp.data(0x20)
        self.disp.clear()
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
        except Exception:
            self.battery_level = "Battery N/A"
        self.refresh()

    def show_message(self, message, color="BLACK"):
        self.scrollable = False
        self.current_message = message
        self.current_color = color
        size = (320, 240)
        background = Image.new("RGB", size, (240, 255, 180))
        draw = ImageDraw.Draw(background)
        font = ImageFont.truetype(os.path.join(os.path.dirname(__file__), '../Font/Font02.ttf'), FONT_SIZE)
        self.current_font = font
        battery_font = ImageFont.truetype(os.path.join(os.path.dirname(__file__), '../Font/Font02.ttf'), FONT_SIZE - 5)
        self.battery_font = battery_font

        lines = message.split('\n')
        self.current_lines = lines
        text_height = len(lines) * FONT_SIZE
        self.current_text_height = text_height

        y = (size[1] - text_height) // 2 + 30
        self.current_y = y
        self.update_battery_level()

        if text_height > size[1] - 20:
            self.current_y = 30
            self.scrollable = True
            self.draw_text()
        else:
            self.scrollable = False
            y_offset = y
            for line in lines:
                draw.text((5, y_offset), line, fill=color, font=font)
                y_offset += FONT_SIZE
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
            y_offset += FONT_SIZE

        battery_padding = 10
        battery_text_height = 20
        battery_area_height = battery_text_height + battery_padding
        draw.rectangle((0, 0, size[0], battery_area_height), fill=(240, 255, 180))
        
        draw.text((5, 5), self.battery_level, fill="BLACK", font=self.battery_font)
        
        self.disp.ShowImage(background.rotate(180))

    def refresh(self):
        if self.current_message:
            self.draw_text()

    def show_list(self, items, selected_index, horizontal_scroll_offset=0):
        size = (320, 240)
        background = Image.new("RGB", size, (240, 255, 180))
        draw = ImageDraw.Draw(background)
        font = ImageFont.truetype(os.path.join(os.path.dirname(__file__), '../Font/Font02.ttf'), FONT_SIZE)

        max_visible_items = size[1] // FONT_SIZE - 2
        if selected_index < self.scroll_offset:
            self.scroll_offset = selected_index
        elif selected_index >= self.scroll_offset + max_visible_items:
            self.scroll_offset = selected_index - max_visible_items + 1

        for i, item in enumerate(items):
            if self.scroll_offset <= i < self.scroll_offset + max_visible_items:
                color = "RED" if i == selected_index else "BLACK"
                draw.text((10 + horizontal_scroll_offset, 30 + (i - self.scroll_offset) * 30), item, fill=color, font=font)
        draw.text((5, 5), self.battery_level, fill="BLACK", font=self.battery_font)
        self.disp.ShowImage(background.rotate(180))
    
    def clear(self):
        self.disp.reset()
        self.disp.clear()

class ListMenu:
    def __init__(self, display):
        self.display = display
        self.stealth_text = "Stealth mode (ON)" if STEALTH_MODE else "Stealth mode (OFF)"
        self.items = ["Get sniffer list", "Get access point list", "Focus/Ignore network", "Create recording", "Restart"]
        self.selected_index = 0
        self.currently_in = "menu"

    def navigate(self, direction="NONE"):
        display.scroll_offset = 0
        if direction == "UP":
            self.selected_index = (self.selected_index - 1) % len(self.items)
        elif direction == "DOWN":
            self.selected_index = (self.selected_index + 1) % len(self.items)
        sleep(0.1)
        self.display.show_list(self.items, self.selected_index)
        self.currently_in = "menu"

    def select(self):
        self.currently_in = self.items[self.selected_index]
        return self.items[self.selected_index]

class NetworksList:
    def __init__(self, display, networks=[]):
        self.display = display
        self.items = networks
        self.selected_index = 0
        self.selected_bssid = None
        self.horizontal_scroll_offset = 0
    
    def navigate(self, direction="NONE"):
        if direction == "UP":
            self.selected_index = (self.selected_index - 1) % len(self.items)
        elif direction == "DOWN":
            self.selected_index = (self.selected_index + 1) % len(self.items)
        elif direction == "LEFT" and self.horizontal_scroll_offset < 0:
            self.horizontal_scroll_offset += 40
        elif direction == "RIGHT" and self.horizontal_scroll_offset > -self.get_max_horizontal_scroll():
            self.horizontal_scroll_offset -= 40
        sleep(0.1)
        self.display.show_list(self.items, self.selected_index, self.horizontal_scroll_offset)

    def select(self):
        return self.items[self.selected_index]

    def get_max_horizontal_scroll(self):
        max_length = max([len(item) for item in self.items])
        return max_length * FONT_SIZE - 320

class NetworkOptionsList:
    def __init__(self, display, selected_bssid=None):
        self.display = display
        self.items = ["Focus network", "Ignore network"]
        self.selected_index = 0
        self.selected_bssid = selected_bssid

    def navigate(self, direction="NONE"):
        if direction == "UP":
            self.selected_index = (self.selected_index - 1) % len(self.items)
        elif direction == "DOWN":
            self.selected_index = (self.selected_index + 1) % len(self.items)
        sleep(0.1)
        self.display.show_list(self.items, self.selected_index)
    
    def select(self):
        return self.items[self.selected_index]

class ButtonHandler:
    def __init__(self, menu, display):
        self.menu = menu
        self.display = display
        self.networks_list = None
        self.network_options_list = None
        GPIO.setmode(GPIO.BCM)
        for pin in BUTTON_PINS.keys():
            GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)
        self.action_map = {
            "UP": self.handle_up_down,
            "DOWN": self.handle_up_down,
            "LEFT": self.handle_left_right,
            "RIGHT": self.handle_left_right,
            "ACCEPT": self.handle_accept,
            "REFUSE": self.handle_refuse
        }

    def listen(self):
        while True:
            for pin, action in BUTTON_PINS.items():
                if GPIO.input(pin) == GPIO.HIGH:
                    if action in self.action_map:
                        self.action_map[action](action)

    def handle_up_down(self, action):
        if self.menu.currently_in == "menu":
            self.menu.navigate(action)
        elif self.menu.currently_in == "networks":
            self.networks_list.navigate(action)
        elif self.menu.currently_in == "network_options":
            self.network_options_list.navigate(action)
        elif self.display.scrollable:
            if action == "UP" and self.display.scroll_offset > 0:
                self.display.scroll_offset -= 40
                self.display.refresh()
            elif action == "DOWN" and self.display.scroll_offset < self.display.current_text_height - 240:
                self.display.scroll_offset += 40
                self.display.refresh()

    def handle_left_right(self, action):
        if self.menu.currently_in == "networks":
            self.networks_list.navigate(action)
        elif not self.menu.currently_in in ["menu", "network_options"]:
            if action == "LEFT" and self.display.horizontal_scroll_offset < 0:
                self.display.horizontal_scroll_offset += 40
                self.display.refresh()
            elif action == "RIGHT" and self.display.horizontal_scroll_offset > self.display.current_font.getbbox(self.display.current_message)[1] - 320:
                self.display.horizontal_scroll_offset -= 40
                self.display.refresh()

    def handle_accept(self, action):
        if self.menu.currently_in == "menu":
            selected = self.menu.select()
            self.handle_accept_action(selected)
        elif self.menu.currently_in == "networks":
            selected_network = self.networks_list.select()
            self.network_options_list = NetworkOptionsList(self.display, selected_network.split(',')[1].strip(" ']").replace(":", "-"))
            self.menu.currently_in = "network_options"
            self.network_options_list.navigate()
        elif self.menu.currently_in == "network_options":
            selected_option = self.network_options_list.select()
            self.handle_network_option_action(selected_option, self.network_options_list.selected_bssid)

    def handle_refuse(self, action):
        if not self.menu.currently_in == "menu":
            self.menu.navigate("NONE")
            self.display.scroll_offset = 0

    def handle_accept_action(self, selected):
        if selected == "Get sniffer list":
            self.display.show_message(client.get_sniffer_list())
        elif selected == "Get access point list":
            self.display.show_message(client.get_access_point_list())
        elif selected == "Create recording":
            self.display.show_message(client.create_recording())
        elif selected == "Get battery":
            self.display.show_message(client.get_battery())
        elif selected == "Stealth mode" and not STEALTH_MODE:
            os.system("systemctl stop hostapd")
            self.display.show_message("Stealth mode ENABLED!", "GREEN")
        elif selected == "Stealth mode" and STEALTH_MODE:
            os.system("systemctl start hostapd")
            self.display.show_message("Stealth mode DISABLED!", "GREEN")
        elif selected == "Focus/Ignore network":
            self.handle_focus_ignore()
        elif selected == "Restart":
            self.cleanup()

    def handle_focus_ignore(self):
        networks = client.get_networks_list()
        self.networks_list = NetworksList(self.display, networks)
        self.menu.currently_in = "networks"
        self.networks_list.navigate()

    def handle_network_option_action(self, selected_option, bssid):
        if selected_option == "Focus network":
            self.display.show_message(client.start_focus(bssid))
        elif selected_option == "Ignore network":
            self.display.show_message(client.ignore_AP(bssid))
        self.menu.currently_in = "menu"

    def cleanup(self):
        self.display.clear()
        os.system('sudo reboot')

if __name__ == "__main__":
    try:
        display = Display()
        menu = ListMenu(display)
        button_handler = ButtonHandler(menu, display)
        client = client.Client()
        for i in range(4):
            if not client.is_connected():
                display.show_message("Failed to connect to server! Retrying...", "RED")
                sleep(3)
        if not client.is_connected():
            display.show_message("Failed to connect to server!", "RED")
            sleep(2)
            display.clear()
            sys.exit()
        else:
            display.show_message("Connected to sniffer!", "GREEN")
            sleep(1)
        menu.navigate()
        button_handler.listen()
    except KeyboardInterrupt:
        GPIO.cleanup()
        sys.exit()
    except RuntimeError as e:
        print(f"Runtime error: {e}")
        GPIO.cleanup()
        sys.exit()