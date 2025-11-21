/*jshint sub:true*/
/* LOAD USERS.JS AS WELL */
// synced skorie1,2,3 15sep25

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


    var url = USERS_API_URL + "userlist/?"+query;
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
                    if (payload[i]['date_joined']) {
                        payload[i]['date_joined'] = payload[i]['date_joined'].substring(0, 10);
                    }
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

    //     // can block panes, eg. if only a few entries, by settings panes to []
    // if (typeof panes != "undefined" && panes.length > 0) {
    //     table_options['searchPanes'] =  {
    //         viewTotal: true,
    //         columns: panes,
    //     };
    //     table_options['select'] = true;
    //     table_options['dom'] = 'Plfrtip';
    //
    // }

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
            if (d.keycloak_id) {
                document.location.href = "/users/admin_user/" + d.keycloak_id + "/?next=user-browser";
            } else {
                 document.location.href = "/users/admin_user/" + d.id + "/?next=user-browser";
            }
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


function show_user_table_paged(selection, page_length, columns, query, panes, col_reorder) {
    // use for larger number of users - paged, no panes.  Use for > 3000

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


    const url = USERS_API_URL + "userlist_paged/?"+query;


const table_options = {
  language: { processing: "Loading data..." },
  pageLength: page_length,
    lengthMenu: [[100, 500, 1000], [100, 500, 1000]],
  stateSave: true,
  responsive: { details: false },
  serverSide: true,
  processing: true,

  ajax: function (data, callback) {
    // Map DT -> DRF
    const page = Math.floor(data.start / data.length) + 1;
    const page_size = data.length;

    let ordering = null;
    if (data.order && data.order.length) {
      const colIdx = data.order[0].column;
      const dir = data.order[0].dir; // 'asc'|'desc'
      const colName = data.columns[colIdx].name || data.columns[colIdx].data;
      if (colName) ordering = (dir === 'desc' ? '-' : '') + colName;
    }

    $.getJSON(url, {
      page,
      page_size,
      search: data.search?.value || '',
      ...(ordering ? { ordering } : {})
    }, function (resp) {
      const rows = (resp.results || []).map(r => ({
        ...r,
        date_joined: r.date_joined ? r.date_joined.substring(0, 10) : r.date_joined,
        last_login:  r.last_login  ? r.last_login.substring(0, 10)  : r.last_login
      }));

      callback({
        draw: data.draw,
        recordsTotal: resp.count,
        recordsFiltered: resp.count, // if server returns a filtered count, use it here
        data: rows
      });
    });
  },

  columns: columns,
  colReorder: { order: col_reorder },
  select: true,
  dom: 'Blfrtip',
buttons: [
  {
    text: '<i class="bi bi-person-plus"></i> Add User',
    className: 'btn btn-primary',
    action: function (e, dt, node, config) {
      // what happens when the button is clicked
      window.location.href = '/users/add_user/';
    }
  },
  'csv'
],

};

const dt = $(selection).DataTable(table_options);

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
            if (d.keycloak_id) {
                document.location.href = "/users/admin_user/" + d.keycloak_id + "/?next=user-browser";
            } else {
            document.location.href = "/users/admin_user/" + d.id + "/?next=user-browser";
            }
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
function check_user(callback) {

    $("#check_user").html("Checking if already setup...");

    // first check if they are already signed up locally

    $.ajax({
        method: "POST",   // using post so that email does not appear in logs
        url: USERS_API_URL + "email_exists/?detail=True",
        data: {'email': $("#check_email").val()},

    })
        .done(function (data) {

            if ("username" in data && data.username.length) {
                $("#username").val(data.username);
                $("#user_id").val(data.id);
                $("#id_email").val(data.email);
                $("#id_first_name").val(data.first_name);
                $("#id_last_name").val(data.last_name);
                $("#id_mobile").val(data.mobile);
                $("#id_whatsapp").val(data.whatsapp);
                $("#message_div").fadeIn();
                $(".user_email").html(data.email);
                $(".user_name").html(data.first_name + " " + data.last_name);


                // can have scenaio with keycloak user but no local one (maybe joined another skorie)
                // so don't want to continue check nos

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
                            // if user_pk hidden field exists then set to keycloak_id
                            if ($("#user_pk").length) {
                                $("#user_pk").val(d.id);
                            }
                            if (d.enabled && d.emailVerified) {
                                $("#in_keycloak_and_local").slideDown();
                            } else {
                                $("#in_keycloak_not_local").slideDown();
                            }

                        }
                    }
                    if (callback) {
                        callback(d);
                    }


                });
            } else {
                               $("#message").html("<p>No user with this email exists.</p>");
                        // reveal rest of form for admin to fill in
                        $("#add_user_form").slideDown();
  }
        })
        .fail(function (xhr, status, error) {
            console.log('failed' + status)
        });
}

function get_user_signup_info(email, callback) {
    // same as version in users.js
    $.ajax({
        method: "POST",
        url: USERS_API_URL + "email_exists_on_keycloak_p/",
        data: {'email': email},

        success: function (d) {

            d.not_registered = !(d.django_is_active && d.keycloak_enabled);

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
function send_otp_via_channel(payload) {
    return new Promise((resolve, reject) => {
        $.ajax({
            method: "POST",
            url: USERS_API_URL + "comms_otp/",
            data: payload,
        })
            .done(resolve)
            .fail((xhr, status, error) => {
                console.log('Failed:', status, error);
                reject(error);
            });
    });
}


function email_exists_keycloak(email, callback) {
    $.ajax({
        method: "POST",
        url: USERS_API_URL + "email_exists_on_keycloak/",
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
        url: USERS_API_URL + "users/" + payload.id + "/",
        data: payload,
    })
        .done(function (data) {
            console.log(data);
        })
        .fail(function (xhr, status, error) {
            console.log('failed' + status)
        });
}


function set_keycloak_password(payload) {

    return new Promise((resolve, reject) => {
        $.ajax({
            method: "POST",
            url: USERS_API_URL + "set_temp_password/",
            data: payload,
        })
            .done(resolve)
            .fail((xhr, status, error) => {
                console.log('Failed:', status, error);
                reject(error);
            });
    });
}



function check_user_exists(email, callback, error_callback) {
    $.ajax({
        method: "POST",
        url: USERS_API_URL + "email_exists_or_404/",
        data: {'email': email.toLowerCase()},

    })
        .done(function (data) {
            if (callback) {
                callback(data);
            }
        })
        .fail(function (xhr, status, error) {
            if (error_callback) {
                error_callback("Invalid email");
            }
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


function usersearch(callback) {
    $('.search4user').tinyAutocomplete({
        url: USERS_API_URL + "members",
        maxItems: 7,
        showNoResults: true,
        markAsBold: false,
        wrapClasses: "autocomplete bootstrapped",
        itemTemplate: '<li class="autocomplete-item">{{name}} - {{email}}</li>',
        onSelect: function (el, val) {

            if (typeof callback != "undefined") {
                callback(val);
            }




        }
    });
}


function toggleRoles(username, role, active) {

    var payload = {username: username,
        role: role,
        active: active};

    var url = USERS_API_URL + "toggle_role/";

    $.ajax({
        method: "PATCH",
        url: url,
        data: payload,

    }).done(function (data) {

        console.log("done");

    }).fail(function (jqXHR, textStatus) {

        console.log('failed to connect to server');

    });

}


function get_user_roles(email) {

    // uncheck all
    $('.role').prop('checked', false);

    $.ajax({
        method: "GET",
        url:USERS_API_URL + "members/",
        data: {email: email},
        cache: false,

    }).done(function (data) {

        $("#roles").fadeOut();
        if (data.length == 1) {
            var d = data[0];

            // save ref for this user
            $("#username").val(d.username);


            // check roles for this user
            d.roles.forEach((function(role) {
                $("#role_" + role).prop('checked', 'checked');

            }));

            $("#roles").fadeIn();
        }

    });
}

function activate_user(userid) {
    // we are activating both django and keycloak here
    // previously just doing active
    const url = USERS_API_URL + "users/" + userid + "/activate_both/";
    $.ajax({
        method: "GET",
        url: url,
    }).done(function (data) {
        console.log("done");
    }).fail(function (jqXHR, textStatus) {
        console.log('failed api call to '+url+' with error: ' + textStatus);
    });
}

function deactivate_user(userid) {
    // note we are not deactivating the keycloak user here as other apps may not want to do that
    // so this just deactivates the user in this django app
    const url = USERS_API_URL + "users/" + userid + "/deactivate/";
    $.ajax({
        method: "GET",
        url: url
    }).done(function (data) {
        console.log("done");
    }).fail(function (jqXHR, textStatus) {
        console.log('failed api call to '+url+' with error: ' + textStatus);
    });
}

function verify_user(userid) {
    $.ajax({
        method: "GET",
        url: USERS_API_URL + "users/" + userid + "/verify/",
    }).done(function (data) {
        console.log("done");
    }).fail(function (jqXHR, textStatus) {
        console.log('failed to connect to server');
    });
}
