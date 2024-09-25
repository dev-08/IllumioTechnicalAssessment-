import java.io.*;
import java.util.*;

public class FlowLogTagger {

    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            System.out.println("Usage: java FlowLogTagger <flow_log_file> <lookup_table_file>");
            return;
        }

        String flowLogFile = args[0];
        String lookupTableFile = args[1];

        // Step 1: Read the lookup table
        Map<String, String> lookupTable = loadLookupTable(lookupTableFile);

        // Step 2: Process the flow logs
        List<String> flowLogs = readFlowLogs(flowLogFile);
        Map<String, Integer> tagCounts = new HashMap<>();
        Map<String, Integer> portProtocolCounts = new HashMap<>();

        for (String log : flowLogs) {
            // Step 3: Extract dstport and protocol from the log
            String[] logParts = log.split(" ");
            String dstPort = logParts[5];
            String protocol = getProtocolString(logParts[7]); // Convert protocol number to string (tcp/udp/icmp)

            // Step 4: Check for a match in the lookup table
            String key = dstPort + "," + protocol;
            String tag = lookupTable.getOrDefault(key, "Untagged");

            // Increment tag counts
            tagCounts.put(tag, tagCounts.getOrDefault(tag, 0) + 1);

            // Increment port/protocol combination counts
            String portProtocolKey = dstPort + "," + protocol;
            portProtocolCounts.put(portProtocolKey, portProtocolCounts.getOrDefault(portProtocolKey, 0) + 1);
        }

        // Step 5: Output the results
        writeTagCounts(tagCounts);
        writePortProtocolCounts(portProtocolCounts);
    }

    // Reads the lookup table and returns a map with dstport,protocol as the key and
    // tag as the value
    private static Map<String, String> loadLookupTable(String lookupTableFile) throws IOException {
        Map<String, String> lookupTable = new HashMap<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(lookupTableFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length == 3) {
                    String key = parts[0] + "," + parts[1].toLowerCase(); // Combine dstport and protocol
                    lookupTable.put(key, parts[2]);
                }
            }
        }
        return lookupTable;
    }

    // Reads the flow logs from the file and returns a list of log entries
    private static List<String> readFlowLogs(String flowLogFile) throws IOException {
        List<String> logs = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(flowLogFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                logs.add(line);
            }
        }
        return logs;
    }

    // Converts protocol number to its string equivalent
    private static String getProtocolString(String protocolNumber) {
        switch (protocolNumber) {
            case "6":
                return "tcp";
            case "17":
                return "udp";
            case "1":
                return "icmp";
            default:
                return "unknown";
        }
    }

    // Writes the tag counts to a file
    private static void writeTagCounts(Map<String, Integer> tagCounts) throws IOException {
        try (PrintWriter writer = new PrintWriter(new FileWriter("tag_counts.csv"))) {
            writer.println("Tag,Count");
            for (Map.Entry<String, Integer> entry : tagCounts.entrySet()) {
                writer.println(entry.getKey() + "," + entry.getValue());
            }
        }
    }

    // Writes the port/protocol combination counts to a file
    private static void writePortProtocolCounts(Map<String, Integer> portProtocolCounts) throws IOException {
        try (PrintWriter writer = new PrintWriter(new FileWriter("port_protocol_counts.csv"))) {
            writer.println("Port,Protocol,Count");
            for (Map.Entry<String, Integer> entry : portProtocolCounts.entrySet()) {
                writer.println(entry.getKey() + "," + entry.getValue());
            }
        }
    }
}
