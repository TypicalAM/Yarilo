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
        return str(response)

    def get_access_point_list(self):
        response = self.stub.AccessPointList(service_pb2.Empty())
        return str(response)
    
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
        response = self.stub.BatteryGetLevel(service_pb2.Empty())
        return str(response)