

// from index and what next page



$(document).on("click", "#signup", function() {

    $("#id_user_type").val($("input[name='first_user_type']:checked").val());
    signinup();

});

$(document).on("blur", "#id_email", function() {
    //TOODO: proper test for a valid email here
    if ($(this).val().length > 5) {

        $.ajax({
        url: USERS_API_URL + "email_exists/",
            type: 'get',
            data: {'email': $(this).val()},
            error: function (xhr, ajaxOptions, thrownError) {
                alert(thrownError);
            },
            success: function (result) {
                if (typeof result.active != "undefined" && result.active) {
                    $("#continue").html("Login");

                } else {
                    // warning - this html value is check below in submitHandler
                    //TODO: better way of knowing if you are in signup mode
                    $("#continue").html("Signup");

                }
            }
        });
    }

});


$("#signinup_form").validate({
    rules: {


        email: {
            required: true,
            email:true
        },
        password: {
            required: true,
            minlength: 5
        },

    },


    errorElement : 'div',
    errorPlacement: function(error, element) {
        var placement = $(element).data('error');
        if (placement) {
            $(placement).append(error);
        } else {
            error.insertAfter(element);
        }
    },
    submitHandler: function(form) {

        // in signup mode
        if ( $("#continue").html() == "Signup") {
            $("#unkonwn_email").html($("#id_email").val());
            $("#confirm_signup").modal("open");
        } else {
            signinup();
        }
    }
});


$('input').keypress(function (e) {
    if (e.which == 13) {
        $("#signinup_form").submit();
        return false;
    }
});



function signinup() {
    var data = $("#signinup_form").serialize() ;


    $.ajax({
        url: '/signinup/',
        type: 'post',
        data: data,
        error: function (xhr, ajaxOptions, thrownError) {
            alert(thrownError);
        },
        success: function (result) {
            if (result.result == "OK") {
                document.location.href = $("[name=next]").val();

                // force reload of data as may have more tests now logged in
                simpleStorage.deleteKey("LAST_REFRESH");

            } else {

                    document.location.href = "/login/";

            }
        }
    });

}
