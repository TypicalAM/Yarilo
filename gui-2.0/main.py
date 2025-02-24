from display import Display
from pages.main_menu import MainMenu
from button_handler import ButtonHandler
from pages.page import Page
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
    main_menu = MainMenu(display)
    Page.pages_stack.append(main_menu)
    display.current_page = main_menu
    main_menu.render()

    bh = ButtonHandler(callback=button_callback)

    try:
        while True:
            main_menu.batt_bar.set_level(25)
            sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        display.cleanup()

if __name__ == "__main__":
    main()