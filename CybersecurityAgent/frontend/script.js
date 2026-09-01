async function loadProcesses() {

    try {

        const response =
            await fetch("http://127.0.0.1:8000/processes");


        const processes =
            await response.json();


        const table =
            document.getElementById("process-table");


        table.innerHTML = "";


        processes.forEach(process => {

            const row =
                document.createElement("tr");


            row.innerHTML = `

                <td>
                    ${process.timestamp}
                </td>

                <td>
                    ${process.pid}
                </td>

                <td>
                    ${process.process_name}
                </td>

                <td>
                    ${process.cpu_percent.toFixed(2)}%
                </td>

                <td>
                    ${process.memory_percent.toFixed(2)}%
                </td>

            `;


            table.appendChild(row);

        });


        document.getElementById(
            "total-records"
        ).textContent = processes.length;


    }

    catch (error) {

        console.error(
            "Failed to load processes:",
            error
        );

    }

}


loadProcesses();