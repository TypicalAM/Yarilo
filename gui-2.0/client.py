import grpc
import os
import sys
sys.path.append(os.path.dirname(__file__))
import service_pb2, service_pb2_grpc

class Client:
    def __init__(self, host='localhost', port=9090):
        self.channel = grpc.insecure_channel(f'{host}:{port}')
        self.stub = service_pb2_grpc.SnifferStub(self.channel)
        # Cache the primary sniffer if available
        self._sniffer_uuid = None

    def _get_primary_sniffer_uuid(self):
        if self._sniffer_uuid is None:
            response = self.stub.SnifferList(service_pb2.Empty())
            if response.sniffers:
                self._sniffer_uuid = response.sniffers[0].uuid
            else:
                raise ValueError("No sniffers found.")
        return self._sniffer_uuid

    def is_connected(self):
        try:
            self.stub.SnifferList(service_pb2.Empty())
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
        sniffers = [
            f"uuid: {sniffer.uuid} interface name: {sniffer.net_iface_name}\nfilename: {sniffer.filename}\n"
            for sniffer in response.sniffers
        ]
        return "Sniffers:\n" + "\n".join(sniffers)

    def get_access_point_list(self):
        try:
            uuid = self._get_primary_sniffer_uuid()
            request = service_pb2.APGetRequest(sniffer_uuid=uuid)
            response = self.stub.AccessPointList(request)
            if not response.nets:
                return "No access points found."
            access_points = [f"{ap.ssid} - {ap.bssid}\n" for ap in response.nets]
            return "Access Points:\n" + "".join(access_points)
        except ValueError as e:
            return str(e)
    
    def get_networks_list(self):
        try:
            uuid = self._get_primary_sniffer_uuid()
            request = service_pb2.APGetRequest(sniffer_uuid=uuid)
            response = self.stub.AccessPointList(request)
            if not response.nets:
                return "No networks found."
            networks = [str([network.ssid, network.bssid]) for network in response.nets]
            return networks
        except ValueError as e:
            return str(e)

    def create_recording(self):
        try:
            uuid = self._get_primary_sniffer_uuid()
            request = service_pb2.RecordingCreateRequest(
                sniffer_uuid=uuid,
                name='Manual_recording',
                raw=True
            )
            response = self.stub.RecordingCreate(request)
            return str(response)
        except ValueError as e:
            return str(e)
    
    def create_APrecording(self, bssid):
        try:
            uuid = self._get_primary_sniffer_uuid()
            request = service_pb2.APCreateRecordingRequest(
                sniffer_uuid=uuid,
                name='AccessPoint_recording',
                bssid=bssid,
                raw=True
            )
            response = self.stub.RecordingCreate(request)
            return str(response)
        except ValueError as e:
            return str(e)

    def get_battery(self):
        try:
            response = self.stub.BatteryGetLevel(service_pb2.Empty())
            # Use the float value directly from response.percentage
            formated_resp = f"{response.percentage:.0f}"
            formated_resp = int(formated_resp)
            return formated_resp
        except grpc.RpcError as e:
            return "Get battery error"
        
    def start_focus(self, network):
        try:
            uuid = self._get_primary_sniffer_uuid()
            request = service_pb2.FocusStartRequest(
                sniffer_uuid=uuid,
                bssid=network
            )
            response = self.stub.FocusStart(request)
            print(response)
            return str(response)
        except grpc.RpcError as e:
            print(e)
            return "Start focus error"
    
    def get_active_focus(self):
        try:
            uuid = self._get_primary_sniffer_uuid()
            response = self.stub.FocusGetActive(uuid)
            return str(response)
        except grpc.RpcError as e:
            print(e)
            return "Get active focus error"
    
    def ignore_AP(self, network):
        try:
            uuid = self._get_primary_sniffer_uuid()
            request = service_pb2.APIgnoreRequest(
                sniffer_uuid=uuid,
                use_ssid=False,
                bssid=network,
                ssid=""
            )
            response = self.stub.AccessPointIgnore(request)
            return str(response)
        except grpc.RpcError as e:
            print(e)
            return "Ignore AP error"