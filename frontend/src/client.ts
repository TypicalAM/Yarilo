import { GetAPRequest } from './packets_pb';
import { GreeterClient } from './packets_grpc_web_pb';

var client = new GreeterClient('http://localhost:8080');
let button = document.getElementById("test_button");

button.addEventListener('click', () => {
    console.log("Button pressed");
    let request = new GetAPRequest();
    request.setSsid("Coherer");
    client.getAccessPoint(request, {}, function(err, response) {
        console.log("Response:", response)
        console.log("Error:", err)
    })
})
