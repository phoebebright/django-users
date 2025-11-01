//TODO: move rider -> competitor and then matches skorie common?

//TODO: check if email exists and display password field if so.
// if not found rider at this event, ask if using a different name

$(document).on("change", "#id_email", function() {

    //TODO: wait for email to be complete before checking
    $.ajax({
        method: "POST",
        url: USERS_API_URL + "email_exists/",
        dataType: 'json',
        contentType: 'json',
        data: {'email': this.value},

    })
        .done(function (data) {
            if (typeof data === "object") {
                if (data.competitor_name.length) {
                    $("#id_competitor_name").val(data.competitor_name);
                }
            }
        })
        .fail(function (xhr, status, error) {
            console.log('failed' + status);
        });
});

// DOCUMENTATION: https://jqueryvalidation.org/
$("form").validate({
    rules: {
        email: {
            required: true,
            email: true
        },

        competitor_name: {
            required: true,
            minlength: 6
        },


    },


    errorElement: 'span',
    errorPlacement: function (error, element) {

        $(error).addClass('helper-text');
        var placement = $(element).parent().find(".error_message");
        if (placement) {
            $(placement).html(error);
        } else {
            error.insertAfter(element);
        }

    },
    errorClass: 'invalid',
});


$(document).on("click", "#register", function(e) {
    $("form").submit();
});




function check_competitor_is_at_event(competitor_name) {

     $.ajax({
        method: "GET",
        url: SKORIE_API + "/api/v2/riding_at_event/",
        dataType: 'json',
        contentType: 'json',
        data: {'competitor_name': competitor_name},

    })
        .done(function (data) {
            if (typeof data === "object") {
                if (data.competitor_name.length) {
                    $("#id_competitor_name").val(data.competitor_name);
                }
            }
        })
        .fail(function (xhr, status, error) {
            console.log('failed' + status);
        });


}
