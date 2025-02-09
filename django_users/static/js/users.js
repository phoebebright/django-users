            function getQueryParam(param) {
                let urlParams = new URLSearchParams(window.location.search);
                return urlParams.get(param);
            }

  function get_user_signup_info(email, callback) {
    // same as version in admin_users.js
            $.ajax({
                method: "POST",
                url: SKORIE_API + "/api/v2/email_exists_on_keycloak_p/",
                data: {'email': email},

                success: function (d) {

                    d.not_registered = (d.user_id == 0 && d.django_user == 0);

                    let output = "Created: "+(new Date(d.keycloak_created).toLocaleString()).toString()+"<br>";
                    output += "Django is active: " + (d.django_active ? 'Yes' : 'No') + "<br>";
                    if (d.django_user_keycloak_id) {
                        output += "Django linked to Keycloak: " + d.django_user_keycloak_id + "<br>";
                    }
                    output += "Keycloak verified: " + (d.verified ? 'Yes' : 'No') + "<br>";
                    output += "Keycloak enabled: " + (d.enabled ? 'Yes' : 'No') + "<br>";
                    if (d.keycloak_actions) {
                        output += "Keycloak Actions: " + d.keycloak_actions.length ? d.keycloak_actions.join(', ') : 'None' + "<br>";
                    }
                    d.output = output;
                    callback(d);


                },
                error: function () {
                    // If there's an error, show the error message
                    $('#apiError').show();
                    $('#apiResponse').hide();
                }
            });

        }

function problem_login(email){

    $.ajax({
        method: "POST",
        url: SKORIE_API + "/api/v2/email_exists_on_keycloak_p/",
        data: {'email': email},

        success: function (d) {
            const keycloak_id = $('#keycloak_id').val();
            $("#user_id").val(d.user_id);
            $("#keycloak_id").val(d.django_keycloak_user);


            // check django keycloak_id is the same as the one in keycloak - if there is one
            if (d.channels ) {
                // for each d.channel create a button to click
                $('#existing_channels').html('');
                d.channels.forEach(function (item) {
                    if (item.email) {
                        $('#existing_channels').append('<button  class="btn btn-primary verify w-100 mt-1" data-channel_pk="' + item.channel_id + '">Send Email to ' + item.email + '</button>');
                    } else {
                        $('#existing_channels').append('<button  class="btn btn-primary verify w-100 mt-1" data-channel_pk="' + item.channel_id + '">Send SMS to ' + item.mobile + '</button>');
                    }
                });


            }  else if (d.user_id == 0 && d.django_keycloak_user == 0) {
                $('#result').html('<div class="alert alert-danger" role="alert">This email has not been registered.  Check you have entered the email correctly above or sign up again. <a href="'+register_url+'?email='+email+'" class="btn btn-primary-outline">'+REGISTER_TERM+'</div>');
                $("#result").slideDown();
                return;
            } else if (d.user_id && d.django_keycloak_user ) {
                if (d.user_id != d.django_keycloak_user) {
                    $('#result').html('<div class="alert alert-danger" role="alert">The email you entered is already in use by another account.</div>');
                    $("#result").slideDown();
                    return;
                }
            }


            if (d.keycloak_verified) {
                $('#result').html(`
    <div class="alert alert-success" role="alert">
        Your account is verified and ready to use. Have you forgotten your password? 
        <a href="${forgot_pw_url}?email=${encodeURIComponent(email)}" class="text-primary">Yes</a><br />
        Try <a href="${login_url}?email=${encodeURIComponent(email)}" class="change_password_now text-primary">
            ${LOGIN_TERM}
        </a>
 
    </div>
`);

                $("#id_email").val(email);
                $("#id_password").focus();
                $(".login_form_div").slideDown();
            } else {
                $('#result').html('<div class="alert alert-warning" role="alert">Your account is not yet verified. </div>');
                $("#verify_how").slideDown();

            }
            $("#result").slideDown();

        },
        error: function () {
            // If there's an error, show the error message
            $('#apiError').show();
            $('#apiResponse').hide();
        }
    });
}


// Function to check if the email is valid
function validateEmail(email) {
    let emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailPattern.test(email);
}

// Check the email validity and update form state accordingly
function checkEmail() {
    let email = emailInput.val();
    if (validateEmail(email)) {
        emailInput.removeClass('is-invalid').addClass('is-valid');
        submitBtn.prop('disabled', false);
    } else {
        emailInput.removeClass('is-valid').addClass('is-invalid');
        submitBtn.prop('disabled', true);
    }
}

// Function to validate phone number (basic regex for international numbers)
function validatePhoneNumber(phoneNumber) {
    let phonePattern = /^\+?[1-9]\d{1,14}$/;  // Basic pattern for international phone numbers
    return phonePattern.test(phoneNumber);
}

// Validate phone number and show 'Send SMS' button
$('#phone_number').on('input', function () {
    let phoneNumber = $(this).val();
    let sendSmsBtn = $('#sendSmsBtn');
    let submitBtn = $('#submitBtn');

    if (validatePhoneNumber(phoneNumber)) {

        $(this).removeClass('is-invalid').addClass('is-valid');

        sendSmsBtn.show();  // Show the 'Send SMS' button once phone number is valid
    } else {
        $(this).removeClass('is-valid').addClass('is-invalid');
        sendSmsBtn.hide();  // Hide the 'Send SMS' button if the phone number becomes invalid
        submitBtn.prop('disabled', true);
    }
});

// Handle 'Send SMS' button click
$('#sendSmsBtn').on('click', function () {
    const user_id = $('#user_id').val();
    const phone_no = $('#phone_number').val();

    if (user_id && phone_no) {
        $.ajax({
            method: "POST",
            url: SKORIE_API + "/api/v2/send_verification_sms/",
            data: {'user_id': user_id, 'phone_no': phone_no},

            success: function (d) {
                pin = d.pin
                $('#sendSmsContainer').hide();
                $('#pinInputContainer').slideDown();
            },
            fail: function(d) {
                $('#sendSmsContainer').hide();
                $('#pinInputContainer').slideDown();

            }
        });
    }

});

// Validate the PIN input when entered
$('#pin').on('input', function () {
    let enteredPin = $(this).val();
    let submitBtn = $('#submitBtn');
    const user_id = $('#user_id').val();
    const phone_no = $('#phone_number').val();

    if (enteredPin.length === 6 && enteredPin === pin) {
        $(this).removeClass('is-invalid').addClass('is-valid');

        $.ajax({
            method: "POST",
            url: SKORIE_API + "/api/v2/verify_user_with_sms/",
            data: {'user_id': user_id, 'phone_no':phone_no },
            success: function (d) {
                $('#result').html('<div class="alert alert-success" role="alert">Your account has been verified, you can now login <a href='+login_url+' class="btn btn-success-outline">Signin</a></div>');
            },
            error: function () {
                $('#result').html('<div class="alert alert-danger" role="alert">There was an error verifying your account</div>');
            }
        });
    } else {
        $(this).removeClass('is-valid').addClass('is-invalid');

    }
});

$(document).on("click", ".goto_problem_login", function () {
    const email = encodeURIComponent($('#id_email').val());
    document.location.href = problem_login_url + '?email=' + email;
});
$(document).on("click", ".goto_problem_register", function () {
    const email = encodeURIComponent($('#id_email').val());
    document.location.href = problem_register_url + '?email=' + email;
});
