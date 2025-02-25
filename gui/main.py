from display import Display
from button_handler import ButtonHandler
from pages.main_menu import MainMenu
from pages.page import Page
from pages.feedback_page import FeedbackPage
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
    ap_status = False

    display = Display()
    client = Client()

    for i in range(3):
        try:
            if client.is_connected():
                main_menu = MainMenu(display, client, ap_status)
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
                    exit()
            else:
                error_page = FeedbackPage(display, "No connection to server. Retrying.", with_button=False, bg_color="red")
                Page.open_page(error_page)
                error_page.render()
                sleep(5)
        except ValueError as e:
            error_page = FeedbackPage(display, "No connection to server. Retrying.", with_button=False, bg_color="red")
            Page.open_page(error_page)
            error_page.render()
            sleep(5)

if __name__ == "__main__":
    main()