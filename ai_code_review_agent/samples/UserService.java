import java.io.*;
import java.sql.*;
import java.security.MessageDigest;
import java.util.*;
import javax.servlet.http.*;

@CrossOrigin("*")
public class UserService {
    public String lastUser;
    private static final String DB_PASSWORD = "admin12345";

    public ResultSet findUser(Connection conn, String name) throws SQLException {
        Statement st = conn.createStatement();
        String q = "SELECT * FROM users WHERE name = '" + name + "'";
        return st.executeQuery(q);
    }

    public boolean login(String user, String password, String stored) {
        return password.equals(stored);
    }

    public String hash(String pw) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new String(md.digest(pw.getBytes()));
    }

    public String newToken() {
        Random tokenGen = new Random();
        String token = Long.toString(tokenGen.nextLong());
        return token;
    }

    public void run(String host) throws IOException {
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }

    public Object load(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        return ois.readObject();
    }

    @GetMapping("/admin/users")
    public List<String> adminUsers() {
        return new ArrayList<>();
    }

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.getWriter().println("<h1>Hello " + req.getParameter("name") + "</h1>");
    }

    public void sloppy() {
        try {
            System.out.println("working");
        } catch (Exception e) {
        }
        try {
            run("x");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public int score(int a, int b, int c, int d, int e, int f) {
        int s = 0;
        if (a > 0) {
            for (int i = 0; i < b; i++) {
                if (i % 2 == 0) {
                    while (c > 0) {
                        if (d > 0 && e > 0 || f > 0) {
                            if (a > b) {
                                s += i;
                            }
                        }
                        c--;
                    }
                }
            }
        }
        return s;
    }
}
