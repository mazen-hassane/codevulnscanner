import java.io.*;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.xml.parsers.*;
import org.w3c.dom.Document;

public class VulnerableServlet extends HttpServlet {

    // -----------------------------
    // SQL Injection
    // -----------------------------
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {

        String username = req.getParameter("username");
        String password = req.getParameter("password");

        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test", "root", "");
            Statement stmt = conn.createStatement();

            String query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
            ResultSet rs = stmt.executeQuery(query);

            PrintWriter out = resp.getWriter();
            out.println(rs.next() ? "Login success" : "Fail");

        } catch (Exception e) {
            resp.getWriter().println(e.toString());
        }
    }

    // -----------------------------
    // Unsafe Deserialization
    // -----------------------------
    protected void doPut(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {

        try {
            ObjectInputStream ois = new ObjectInputStream(req.getInputStream());
            Object obj = ois.readObject();

            resp.getWriter().println("Received: " + obj);
        } catch (Exception e) {
            resp.getWriter().println(e.toString());
        }
    }

    // -----------------------------
    // XXE
    // -----------------------------
    public void parseXML(InputStream xml, HttpServletResponse resp) throws IOException {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();

            Document doc = builder.parse(xml);

            resp.getWriter().println(doc.getDocumentElement().getNodeName());

        } catch (Exception e) {
            resp.getWriter().println(e.toString());
        }
    }
}
