from display import Display
from pages.main_menu import MainMenu
from button_handler import ButtonHandler
from pages.page import Page
from client import Client
from time import sleep

def button_callback(channel, button_name):
    if display.current_page:
        if button_name == "UP":
            display.current_page.scroll("up")
        elif button_name == "DOWN":
            display.current_page.scroll("down")
        elif button_name == "LEFT":
            display.current_page.navigate("left")
        elif button_name == "RIGHT":
            display.current_page.navigate("right")
        elif button_name == "ACCEPT":
            focused = display.current_page.focusable_elements[display.current_page.focus_index]
            if hasattr(focused, "press"):
                focused.press()
        elif button_name == "REFUSE":
            Page.go_back(display)
        display.current_page.render()

def main():
    global display
    display = Display()
    client = Client()
    if client.is_connected():
        main_menu = MainMenu(display, client)
        Page.open_page(main_menu)
        main_menu.batt_bar.set_level(client.get_battery())
        main_menu.render()

        bh = ButtonHandler(callback=button_callback)

        try:
            while True:
                sleep(0.1)
        except KeyboardInterrupt:
            pass
        finally:
            display.cleanup()

if __name__ == "__main__":
    main()