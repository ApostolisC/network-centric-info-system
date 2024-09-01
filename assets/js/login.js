function login(){
    var username = $("#username").val();
    var password = $("#password").val();

    $.ajax({
        type: "POST",
        url: "http://127.0.0.1:5000/login",
        data: {
            input1: username,
            input2: password
        },
        success: function(response) {
            //$("#result").html(response);
            console.log(response);
        },
        error: function(xhr, status, error) {
            console.error("AJAX request failed:", error);
        }
    });
}
