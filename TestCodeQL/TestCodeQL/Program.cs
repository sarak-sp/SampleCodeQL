using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

var app = builder.Build();

// Configure the HTTP request pipeline.
//if (!app.Environment.IsDevelopment())
//{
//    app.UseExceptionHandler("/Error");
//    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
//    app.UseHsts();
//}

//app.UseHttpsRedirection();
//app.UseStaticFiles();

//app.UseRouting();

//app.UseAuthorization();

//app.MapRazorPages();

//app.Run();



// === 1) Hard-coded credential + plaintext password check ===
const string adminUser = "admin";
const string adminPassword = "P@ssw0rd123!"; // hard-coded secret (vulnerable)

app.MapPost("/login", async (HttpRequest req) =>
{
    var form = await req.ReadFormAsync();
    var username = form["username"].ToString();
    var password = form["password"].ToString();

    // VULN: Plain-text comparison & hard-coded secret
    if (username == adminUser && password == adminPassword)
        return Results.Ok("Welcome admin (insecure auth).");

    return Results.Unauthorized();
});

// === 2) SQL injection via string concatenation ===
//app.MapGet("/user", (string username) =>
//{
//    // VULN: building SQL with string interpolation -> SQL injection
//    var connString = "Server=localhost;Database=MyDb;Trusted_Connection=True;";
//    using var conn = new SqlConnection(connString);
//    conn.Open();
//    var sql = $"SELECT Id, Username, Email FROM Users WHERE Username = '{username}'";
//    using var cmd = new SqlCommand(sql, conn);
//    using var rdr = cmd.ExecuteReader();
//    if (rdr.Read())
//    {
//        return Results.Json(new { Id = rdr["Id"], Username = rdr["Username"], Email = rdr["Email"] });
//    }
//    return Results.NotFound();
//});

// === 3) Insecure deserialization ===
//app.MapPost("/deserialize", async (HttpRequest req) =>
//{
//    // VULN: Deserializing untrusted data with BinaryFormatter (unsafe)
//    using var ms = new MemoryStream();
//    await req.Body.CopyToAsync(ms);
//    ms.Position = 0;
//    var bf = new BinaryFormatter();
//    var obj = bf.Deserialize(ms); // Danger: may execute malicious types
//    return Results.Ok($"Deserialized type: {obj?.GetType().FullName}");
//});

// === 4) Reflected XSS ===
app.MapGet("/greet", (string name) =>
{
    // VULN: returning unencoded user input inside HTML
    var html = $"<html><body>Hello, <b>{name}</b>!</body></html>";
    return Results.Content(html, "text/html");
});

// === 5) Weak hashing (MD5) ===
app.MapPost("/hash", async (HttpRequest req) =>
{
    var form = await req.ReadFormAsync();
    var input = form["value"].ToString();
    using var md5 = MD5.Create(); // weak, broken for passwords
    var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(input));
    return Results.Ok(Convert.ToHexString(hash));
});

// === 6) Unsafe file upload (path traversal / overwrite risk) ===
app.MapPost("/upload", async (HttpRequest req) =>
{
    var form = await req.ReadFormAsync();
    var file = form.Files.GetFile("file");
    if (file == null) return Results.BadRequest("No file.");

    // VULN: using client-supplied filename directly -> path traversal, overwrite
    var uploads = Path.Combine(AppContext.BaseDirectory, "uploads");
    Directory.CreateDirectory(uploads);
    var target = Path.Combine(uploads, file.FileName); // dangerous
    using var fs = File.Create(target);
    await file.CopyToAsync(fs);
    return Results.Ok($"Saved to {target}");
});

app.Run();
