import grpc
import os
import sys
sys.path.append(os.path.dirname(__file__))
import service_pb2, service_pb2_grpc

class Client:
    def __init__(self, host='localhost', port=9090):
        self.channel = grpc.insecure_channel(f'{host}:{port}')
        self.stub = service_pb2_grpc.SnifferStub(self.channel)

    def is_connected(self):
        try:
            response = self.stub.SnifferList(service_pb2.Empty())
            return True
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                print("gRPC Error: Unable to connect to the server.")
            else:
                print(f"gRPC Error: {e.details()} (Code: {e.code()})")
            return False

    def get_sniffer_list(self):
        response = self.stub.SnifferList(service_pb2.Empty())
        if not response.sniffers:
            return "No sniffers found."
        else:   
            sniffers = [f"uuid: {sniffer.uuid} interface name: {sniffer.net_iface_name}\nfilename: {sniffer.filename}\n" for sniffer in response.sniffers]
            return "Sniffers:\n" + "\n".join(sniffers)

    def get_access_point_list(self):
        uuid = self.stub.SnifferList(service_pb2.Empty()).sniffers[0].uuid
        request = service_pb2.APGetRequest(sniffer_uuid=uuid)
        response = self.stub.AccessPointList(request)
        if not response.nets:
            return "No access points found."
        else:
            access_points = [f"{ap.ssid} - bssid: {ap.bssid}\n" for ap in response.nets]
            return "Access Points:\n" + "".join(access_points)
    
    def get_networks_list(self):
        uuid = self.stub.SnifferList(service_pb2.Empty()).sniffers[0].uuid
        request = service_pb2.APGetRequest(sniffer_uuid=uuid)
        response = self.stub.AccessPointList(request)
        if not response.nets:
            return "No networks found."
        else:
            networks = [str([network.ssid, network.bssid]) for network in response.nets]
            return networks

    def create_recording(self):
        uuid = self.stub.SnifferList(service_pb2.Empty()).sniffers[0].uuid
        request = service_pb2.RecordingCreateRequest(
            sniffer_uuid=uuid,
            name='Manual_recording',
            raw=True
        )
        response = self.stub.RecordingCreate(request)
        return str(response)
    
    def create_APrecording(self, bssid):
        uuid = self.stub.SnifferList(service_pb2.Empty()).sniffers[0].uuid
        request = service_pb2.APCreateRecordingRequest(
            sniffer_uuid=uuid,
            name='AccessPoint_recording',
            bssid=bssid,
            raw=True
        )
        response = self.stub.RecordingCreate(request)
        return str(response)

    def get_battery(self):
        try:
            response = self.stub.BatteryGetLevel(service_pb2.Empty())
            formated_resp = "{:.0f}%".format(float(str(response).strip("percentage: ").replace(",", ".")))
            return f"{formated_resp}"
        except grpc._channel._InactiveRpcError as e:
            return f"Get battery error"
        
    def start_focus(self, network):
        try:
            uuid = self.stub.SnifferList(service_pb2.Empty()).sniffers[0].uuid
            request = service_pb2.FocusStartRequest(
                sniffer_uuid=uuid,
                bssid=network
            )
            response = self.stub.FocusStart(request)
            print(response)
            return str(response)
        except grpc._channel._InactiveRpcError as e:
            print(e)
            return f"Start focus error"
    
    def get_active_focus(self):
        try:
            uuid = self.stub.SnifferList(service_pb2.Empty()).sniffers[0].uuid
            response = self.stub.FocusGetActive(uuid)
            return str(response)
        except grpc._channel._InactiveRpcError as e:
            print(e)
            return f"Get active focus error"
    
    def ignore_AP(self, network):
        try:
            uuid = self.stub.SnifferList(service_pb2.Empty()).sniffers[0].uuid
            request = service_pb2.APIgnoreRequest(
                sniffer_uuid=uuid,
                use_ssid=False,
                bssid=network,
                ssid=""
            )
            response = self.stub.AccessPointIgnore(request)
            return str(response)
        except grpc._channel._InactiveRpcError as e:
            print(e)
            return f"Ignore AP error"

