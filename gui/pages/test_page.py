from widgets import Label, Button, ElementList
from pages.page import Page
from PIL import ImageFont

class TestPage(Page):
    def body(self):
        self.title = Label(50, 10, "Test Page", color="green")
        self.title.font = ImageFont.truetype("Font/Font02.ttf", 24)
        
        self.btn_ok = Button(50, 40, 100, 40, "OK", action=self.sample_action, bg_color="blue", text_color="white")
        
        self.lst = ElementList(50, 100, header="List of items", text_color="black", spacing=1)
        self.lst.add_element(Label(50, 200, "Item 1", color="black"))
        self.lst.add_element(Label(50, 210, "Item 2", color="black"))
        
        self.btn_lst = ElementList(50, 150, header="Buttons", text_color="black", spacing=5)
        self.btn_lst.add_element(Button(50, 160, 100, 20, "Button 1", action=self.sample_action, bg_color="blue", text_color="white"))
        self.btn_lst.add_element(Button(50, 200, 100, 20, "Button 2", action=self.sample_action, bg_color="blue", text_color="white"))
        
        self.add_element(self.title)
        self.add_element(self.btn_ok)
        self.add_element(self.lst)
        self.add_element(self.btn_lst)

    def sample_action(self):
        print("Button Pressed!")