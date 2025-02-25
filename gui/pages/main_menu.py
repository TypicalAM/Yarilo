from widgets import Label, Button, ElementList, BatteryBar
from pages.page import Page
from pages.list_detail_page import ListDetailPage
from pages.green_page import GreenPage
from pages.feedback_page import FeedbackPage
from PIL import ImageFont

class MainMenu(Page):
    def __init__(self, display, client):
        self.client = client
        super().__init__(display)

    def body(self):
        self.batt_bar = BatteryBar(0, 0)

        self.title = Label(None, None, "Yarilo", color="black")
        self.title.font = ImageFont.truetype("Font/Font02.ttf", 24)

        self.ap_list = ElementList(None, None, spacing=5, header="Access Points", text_color="black", clickable=True, action=self.list_pressed, limit_to_five=True)
        self.populate_access_points()

        self.save_recording_btn = Button(None, None, width=300, height=30, text="Save Recording", action=lambda: self.create_recording_with_feedback_page())
        
        self.add_element(self.batt_bar)
        self.add_element(self.title)
        self.add_element(self.ap_list)
        self.add_element(self.save_recording_btn)

    def populate_access_points(self):
        ap_str = self.client.get_access_point_list()
        ap_lines = ap_str.split('\n')[1:]
        for line in ap_lines:
            if line.strip():
                self.ap_list.add_element(Button(None, None, width=300, height=20, text = line, action=self.sample_action))

    def sample_action(self):
        new_page = GreenPage(self.display)
        Page.open_page(new_page)

    def list_pressed(self, elementlist):
        header_text = elementlist.header.text if elementlist.header else "Details"
        detail_elements = elementlist.elements[1:] if elementlist.header else elementlist.elements
        new_page = ListDetailPage(self.display, header_text, detail_elements)
        Page.open_page(new_page)

    def create_recording_with_feedback_page(self):
        response = self.client.create_recording()
        new_page = FeedbackPage(self.display, response)
        Page.open_page(new_page)