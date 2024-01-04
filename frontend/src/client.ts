import { HelloRequest, HelloReply } from './packets_pb';
import { GreeterClient } from './packets_grpc_web_pb';

var client = new GreeterClient('http://localhost:8080');
var request = new HelloRequest();
request.setName("helo");

client.sayHello(request, {}, function(err, response) {
    console.log("Response:", response)
    console.log("Error:", err)
});
