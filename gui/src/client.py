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
            sniffers = [f"uuid: \"{sniffer.uuid}\"\ninterface name: \"{sniffer.net_iface_name}\"\nfilename: \"{sniffer.filename}\"\n" for sniffer in response.sniffers]
            return "Sniffers:\n" + "\n".join(sniffers)

    def get_access_point_list(self):
        uuid = self.stub.SnifferList(service_pb2.Empty()).sniffers[0].uuid
        request = service_pb2.APGetRequest(sniffer_uuid=uuid)
        response = self.stub.AccessPointList(request)
        if not response.nets:
            return "No access points found."
        else:
            access_points = [f"ssid: \"{ap.ssid}\"bssid: \"{ap.bssid}\"\n" for ap in response.nets]
            return "Access Points:\n" + "".join(access_points)
    
    def create_recording(self):
        uuid = self.stub.SnifferList(service_pb2.Empty()).sniffers[0].uuid
        request = service_pb2.RecordingCreateRequest(
            sniffer_uuid=uuid,
            name='My little recording',
            raw=True
        )
        response = self.stub.RecordingCreate(request)
        return str(response)

    def get_battery(self):
        try:
            response = self.stub.BatteryGetLevel(service_pb2.Empty())
            return str(response).strip("percentage: ")
        except grpc._channel._InactiveRpcError as e:
            return f"Get battery error"
