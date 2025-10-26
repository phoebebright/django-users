/*jshint sub:true*/
/*web.entrybrowser.js*/

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


    var url = SKORIE_API + "/api/v2/users/?"+query;
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

    // can block panes, eg. if only a few entries, by settings panes to []
    if (typeof panes != "undefined" && panes.length > 0) {
        table_options['searchPanes'] =  {
            viewTotal: true,
            columns: panes,
        };
        table_options['select'] = true;
        table_options['dom'] = 'Plfrtip';

    }
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

function show_judge_table(selection, page_length, columns, query, panes, col_reorder) {


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


    var url = SKORIE_API + "/api/v2/judges/?"+query;
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

    // can block panes, eg. if only a few entries, by settings panes to []
    if (typeof panes != "undefined" && panes.length > 0) {
        table_options['searchPanes'] =  {
            viewTotal: true,
            columns: panes,
        };
        table_options['select'] = true;
        table_options['dom'] = 'Plfrtip';

    }
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
            document.location.href = "/judgehistory/" + d.ref + "/?next=judge-list";
            loading_off();   // if don't do this then if you go back on the entry screen, this screen remains greyed out
        }
    } );

    // link to row being triggered when you click on links within the row - requires use of icon (so has class bi) and class newpage on cell
    // $(selection + ' tbody').on( 'click', 'tr .newpage', function (e) {
    //     if (e.target.className.includes('bi')) {
    //         e.stopPropagation();
    //         e.preventDefault();
    //         window.open( e.target.parentNode.href, '_blank').focus();
    //     }
    //
    // } );

    loaded();

    $("#user_wrapper").slideDown("slow");

    return dt;
}
