from widgets import Label, Button, ElementList, BatteryBar
from pages.page import Page
from pages.list_detail_page import ListDetailPage
from pages.green_page import GreenPage
from pages.feedback_page import FeedbackPage
from PIL import ImageFont
import os

class MainMenu(Page):
    def __init__(self, display, client, ap_status):
        self.client = client
        self.ap_status = ap_status
        super().__init__(display)

    def body(self):
        self.batt_bar = BatteryBar(0, 0)
        self.batt_bar.set_level(self.client.get_battery())

        self.title = Label(10, 20, "Yarilo", color="black")
        self.title.font = ImageFont.truetype("Font/Font02.ttf", 24)

        self.ap_status_lbl = Label(220, 25, "YariloAP is ON" if self.ap_status else "YariloAP is OFF", color="black")
        self.ap_status_lbl.font = ImageFont.truetype("Font/Font02.ttf", 18)

        self.ap_list = ElementList(None, None, spacing=5, header="Access Points", text_color="black", clickable=True,
                                   action=self.aps_list_pressed, limit_to_five=True)
        self.populate_access_points()

        self.save_recording_btn = Button(None, None, width=300, height=30, text="Save Recording",
                                         action=lambda: self.create_recording_with_feedback_page())
        
        if self.ap_status:
            self.switch_ap_btn = Button(None, None, width=300, height=30, text="Switch YariloAP OFF", action=lambda: self.switch_ap())
        else:
            self.switch_ap_btn = Button(None, None, width=300, height=30, text="Switch YariloAP ON", action=lambda: self.switch_ap())

        self.get_active_focus_btn = Button(None, None, width=300, height=30, text="Get active focus",
                                           action=lambda: self.get_acticve_focus_with_feedback_page())
        
        self.stop_focus_btn = Button(None, None, width=300, height=30, text="Stop focus",
                                           action=lambda: self.stop_focus_with_feedback())
        
        self.get_ignored_btn = Button(None, None, width=300, height=30, text="Get ignored APs",
                                           action=lambda: self.get_ignored_with_feedback_page())


        self.add_element(self.batt_bar)
        self.add_element(self.title)
        self.add_element(self.ap_status_lbl)
        self.add_element(self.ap_list)
        self.add_element(self.save_recording_btn)
        self.add_element(self.switch_ap_btn)
        self.add_element(self.get_active_focus_btn)
        self.add_element(self.stop_focus_btn)
        self.add_element(self.get_ignored_btn)

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
    
    def aps_list_pressed(self, elementlist):
        header_text = elementlist.header.text if elementlist.header else "Details"
        detail_elements = elementlist.elements[1:] if elementlist.header else elementlist.elements
        new_page = ListDetailPage(self.display, self.client, header_text, detail_elements, is_ap_list=True)
        Page.open_page(new_page)

    def create_recording_with_feedback_page(self):
        response = self.client.create_recording()
        new_page = FeedbackPage(self.display, response)
        Page.open_page(new_page)

    def switch_ap(self):
        if self.ap_status == False:
            os.system('systemctl start yarilo-ap')
        elif self.ap_status == True:
            os.system('systemctl stop yarilo-ap')

    def get_acticve_focus_with_feedback_page(self):
        response = self.client.get_active_focus()
        if response == "Get active focus error":
            new_page = FeedbackPage(self.display, "Error getting active focus", with_button=True, bg_color="red")
            Page.open_page(new_page)
        else:
            new_page = FeedbackPage(self.display, f"Active focus log:\n{response}")
            Page.open_page(new_page)
    
    def get_ignored_with_feedback_page(self):
        response = self.client.list_ignored()
        new_page = FeedbackPage(self.display, f"Ignored APs:\n{response}")
        Page.open_page(new_page)

    def stop_focus_with_feedback(self):
        response = self.client.stop_focus()
        if response == "Stop focus error":
            new_page = FeedbackPage(self.display, "Error stopping focus", with_button=True, bg_color="red")
            Page.open_page(new_page)
        else:
            new_page = FeedbackPage(self.display, f"Focus stopped", with_button=True, bg_color="green")
            Page.open_page(new_page)