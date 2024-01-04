const { HelloRequest, HelloReply } = require('./packets_pb.js');
const { GreeterClient } = require('./packets_grpc_web_pb.js');

var client = new GreeterClient('http://localhost:8080');
var request = new HelloRequest("kung fu panda");

client.sayHello(request, {}, function(err, response) {
    console.log("Response:", response)
    console.log("Error:", err)
});
