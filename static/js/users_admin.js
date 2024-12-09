/*jshint sub:true*/

function show_user_table(selection, page_length, columns, query, panes, col_reorder) {


    // https://datatables.net/



    if (typeof elements == "undefined") {
        elements = 'ftr';   // remove header and footer blocks
    }

    if (typeof page_length == "undefined") {
        page_length = 100;
    }


    if (typeof query == "undefined") {
        query = "all";
    }

    if (typeof col_reorder == "undefined") {
        col_reorder = [];
    }


    var url = SKORIE_API + "/api/v2/userlist/?"+query;
    console.log(url);
    var table_options = {
        "language": {
            "processing": "Loading data..."
        },
        pageLength: page_length,
        stateSave: true,
        responsive: {
            details: false // so we can click rows
        } ,

        "ajax": {
            url: url,
            "dataSrc": function ( payload ) {

                for ( var i=0; i<payload.length ; i++ ) {

                    if (payload[i]['last_login']) {
                        payload[i]['last_login'] = payload[i]['last_login'].substring(0, 10);
                    }
                }

                return payload;
            }
        },
        columns: columns,
        colReorder: {order: col_reorder},

    };

    // Configure SearchPanes if panes are provided
    const searchPaneConfig = getSearchPaneConfig(panes);
    if (Object.keys(searchPaneConfig).length > 0) {
        table_options['searchPanes'] = searchPaneConfig;

    }

    table_options['select'] = true;
    table_options['dom'] = 'BPlfrtip';

    table_options['buttons'] = [
        'csv' // Add the CSV export button
    ]

    var csrftoken = $("[name=csrfmiddlewaretoken]").val();
    var dt = $(selection).DataTable( table_options );

    dt.on( 'draw', function () {
        let tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl, {
                container: 'body',
                trigger : 'hover'
            });
        });
    } );

    $(selection + ' tbody').on( 'click', 'tr ', function (e) {
        // prevent row click being triggered when clicking on pdf icon
        if (!e.target.className.includes('bi')) {
            var d = dt.row(this).data();
            loading_on();
            //TODO: add next and include current search.
            document.location.href = "/users/admin_user/" + d.id + "/?next=user-browser";
            loading_off();   // if don't do this then if you go back on the entry screen, this screen remains greyed out
        }
    } );

    // link to row being triggered when you click on links within the row - requires use of icon (so has class bi) and class newpage on cell
    $(selection + ' tbody').on( 'click', 'tr .newpage', function (e) {
        if (e.target.className.includes('bi')) {
            e.stopPropagation();
            e.preventDefault();
            window.open( e.target.parentNode.href, '_blank').focus();
        }

    } );

    loaded();

    $("#user_wrapper").slideDown("slow");

    return dt;
}


function check_user(e) {

    $("#check_user").html("Checking if already setup...");

    // first check if they are already signed up locally

    $.ajax({
        method: "POST",   // using post so that email does not appear in logs
        url: SKORIE_API + "/api/v2/email_exists/?detail=True",
        data: {'email': $("#check_email").val()},

    })
        .done(function (data) {

            if (data.username.length) {
                $("#username").val(data.username);
                $("#id_email").val(data.email);
                $("#id_first_name").val(data.first_name);
                $("#id_last_name").val(data.last_name);
                $("#id_mobile").val(data.mobile);
                $("#id_whatsapp").val(data.whatsapp);
            }

            email_exists_keycloak($("#check_email").val(), function (d) {

                $("#check_user").slideUp();
                $("#id_email").val($("#check_email").val());
                $("#check_email").prop('readonly', true);


                if (d) {
                    if (d.status == "N") {
                        $("#message").html("<p>No user with this email exists.</p>");
                        // reveal rest of form for admin to fill in
                        $("#add_user_form").slideDown();
                    } else {

                        if (d.enabled && d.emailVerified) {
                            $("#in_keycloak_and_local").slideDown();
                        } else {
                            $("#in_keycloak_not_local").slideDown();
                        }

                    }
                }


            });


        })
        .fail(function (xhr, status, error) {
            console.log('failed' + status)
        });
}

function email_exists_keycloak(email, callback) {
    $.ajax({
        method: "POST",
        url: SKORIE_API + "/api/v2/email_exists_on_keycloak/",
        data: {'email': email},

    })
        .done(function (data) {
            callback(data);
        })
        .fail(function (xhr, status, error) {
            console.log('failed' + status)
        });
}

function patch_user(pk, payload) {
    $.ajax({
        method: "PATCH",
        url: SKORIE_API + "/api/v2/users/" + payload.id + "/",
        data: payload,
    })
        .done(function (data) {
            console.log(data);
        })
        .fail(function (xhr, status, error) {
            console.log('failed' + status)
        });
}

function set_keycloak_password(payload, callback) {
    $.ajax({
        method: "POST",
        url: SKORIE_API + "/api/v2/set_temp_password/",
        data: payload,
    })
        .done(function (data) {
            callback(data);
        })
        .fail(function (xhr, status, error) {
            console.log('failed' + status)
        });
}



function check_user_exists(email, callback) {
    $.ajax({
        method: "POST",
        url: SKORIE_API + "/api/v2/email_exists/",
        data: {'email': email},

    })
        .done(function (data) {
            callback(data);
        })
        .fail(function (xhr, status, error) {
            console.log('failed' + status)
        });
}

function getSearchPaneConfig(panes) {
    if (Array.isArray(panes) && panes.every(Number.isInteger)) {
        // Pane list as integers: map directly to column indices
        return {
            viewTotal: true,
            columns: panes
        };
    } else if (Array.isArray(panes) && panes.every(pane => typeof pane === 'object' && 'header' in pane && 'options' in pane)) {
        // Custom pane configurations: map directly to SearchPanes
        return {
            viewTotal: true,
            panes: panes
        };
    } else {
        // Default empty panes
        return {};
    }
}
