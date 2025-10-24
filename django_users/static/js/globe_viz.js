
      async function initGlobe(world_data_url, data, max_count) {
            // Define the chart's dimensions
            const width = 928;
            const marginTop = 46;
            const height = width / 2 + marginTop;
            const sensitivity = 75;

            // Set up the projection for the globe
            let projection = d3.geoOrthographic()
                .scale(250)
                .center([0, 0])
                .rotate([0, -30])
                .translate([width / 2, height / 2]);

            const initialScale = projection.scale();
            let path = d3.geoPath().projection(projection);

            // Create the SVG container
            const svg = d3.select("#map")
                .append("svg")
                .attr("width", width)
                .attr("height", height)
                .attr("viewBox", [0, 0, width, height])
                .attr("style", "max-width: 100%; height: auto;");

            // Append a circle to represent the globe
            let globe = svg.append("circle")
                .attr("fill", "#EEE")
                .attr("stroke", "#FFF")
                .attr("stroke-width", "0.2")
                .attr("cx", width / 2)
                .attr("cy", height / 2)
                .attr("r", initialScale);

            // Set up drag and zoom behavior
            svg.call(d3.drag().on('drag', (event) => {
                const rotate = projection.rotate();
                const k = sensitivity / projection.scale();
                projection.rotate([
                    rotate[0] + event.dx * k,  // Use event.dx and event.dy
                    rotate[1] - event.dy * k
                ]);
                path = d3.geoPath().projection(projection);
                svg.selectAll("path").attr("d", path);
            }))
                .call(d3.zoom().on('zoom', (event) => {
                    if (event.transform.k > 0.3) {
                        projection.scale(initialScale * event.transform.k);
                        path = d3.geoPath().projection(projection);
                        svg.selectAll("path").attr("d", path);
                        globe.attr("r", projection.scale());
                    }
                    else {
                        event.transform.k = 0.3;
                    }
                }));

            let map = svg.append("g");

            // Load the world data from the static folder
            const response = await fetch(world_data_url);
            const globe_data = await response.json();

            // Assuming you have a dataset (like life expectancy or population) in the properties
            // Create a colour scale based on some property in the GeoJSON file (e.g., population, GDP, life expectancy)
            const colourScale = d3.scaleSequential(d3.interpolatePuBuGn)
                .domain([0, max_count]);  // Adjust 'some_property' to your data's property

            // Append countries to the globe and colour them based on the property
            map.append("g")
                .attr("class", "countries")
                .selectAll("path")
                .data(globe_data.features)
                .enter().append("path")
                .attr("class", d => "country_" + d.properties.name.replace(" ", "_"))
                .attr("d", path)
                .attr("fill", function(d) {

                    return data[d.id] ? colourScale(data[d.id]) : "#FFF";  // Default to white if no data is found
                })  // Apply colour scale here
                .style('stroke', 'black')
                .style('stroke-width', 0.3)
                .style("opacity", 0.8);

            // Optional: Add automatic rotation
            d3.timer(function(elapsed) {
                const rotate = projection.rotate();
                const k = sensitivity / projection.scale();
                projection.rotate([
                    rotate[0] - 1 * k,
                    rotate[1]
                ]);
                path = d3.geoPath().projection(projection);
                svg.selectAll("path").attr("d", path);
            }, 200);
        }

          function createCountryTable(selection, data) {

        const tableDiv = d3.select(selection);


        const table = tableDiv.append("table")
          .attr("border", 1)
          .style("width", "100%")
          .style("margin-top", "20px");

        const thead = table.append("thead");
        thead.append("tr")
          .html(`
            <th>Country</th>
            <th>Count</th>
          `);


        const tbody = table.append("tbody");

        data.forEach(d => {
          tbody.append("tr")
            .html(`
              <td>${d.country}</td>
              <td>${d.count}</td>
            `);
        });
      }
