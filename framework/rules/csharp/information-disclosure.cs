// Rule fixtures for framework/rules/csharp/information-disclosure.yml
//
// Semgrep test convention: `ruleid:` asserts the rule must fire on the next
// line, `ok:` asserts it must not. The `ok:` cases encode the precision
// commitment made in each rule's rationale -- above all that logging an
// exception is correct handling and must never be flagged.

using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

public class ErrorsController : ControllerBase
{
    private readonly ILogger<ErrorsController> _logger;

    public ErrorsController(ILogger<ErrorsController> logger) => _logger = logger;

    public IActionResult ExceptionMessageReturned()
    {
        try
        {
            Risky();
        }
        catch (Exception ex)
        {
            // ruleid: devsecops-framework.secure-coding.csharp.exception-message-to-response
            return BadRequest(ex.Message);
        }
        return Ok();
    }

    public IActionResult ExceptionLoggedNotReturned()
    {
        try
        {
            Risky();
        }
        catch (Exception ex)
        {
            // Correct handling: logged server-side, generic message to caller.
            // ok: devsecops-framework.secure-coding.csharp.exception-message-to-response
            _logger.LogError(ex, "operation failed");
            return StatusCode(500, "An internal error occurred.");
        }
        return Ok();
    }

    public IActionResult InterpolatedExceptionReturned()
    {
        try
        {
            Risky();
        }
        catch (Exception ex)
        {
            // ruleid: devsecops-framework.secure-coding.csharp.exception-in-interpolated-response
            return $"Operation failed: {ex.Message}";
        }
        return Ok();
    }

    public IActionResult InterpolatedConstantReturned(string orderId)
    {
        // ok: devsecops-framework.secure-coding.csharp.exception-in-interpolated-response
        return $"Order {orderId} was not found.";
    }

    public IActionResult DatabaseErrorDetailReturned()
    {
        try
        {
            Risky();
        }
        catch (System.Data.SqlClient.SqlException sqlEx)
        {
            // ruleid: devsecops-framework.secure-coding.csharp.database-error-detail-in-response
            return BadRequest(sqlEx.Number);
        }
        return Ok();
    }

    public IActionResult DatabaseErrorLogged()
    {
        try
        {
            Risky();
        }
        catch (System.Data.SqlClient.SqlException sqlEx)
        {
            // ok: devsecops-framework.secure-coding.csharp.database-error-detail-in-response
            _logger.LogError(sqlEx, "database call failed");
            return StatusCode(500, "An internal error occurred.");
        }
        return Ok();
    }

    private void Risky() { }
}

public class StartupUnguarded
{
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        // ruleid: devsecops-framework.secure-coding.csharp.developer-exception-page-unconditional
        app.UseDeveloperExceptionPage();
    }
}

public class StartupGuarded
{
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        if (env.IsDevelopment())
        {
            // ok: devsecops-framework.secure-coding.csharp.developer-exception-page-unconditional
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/error");
        }
    }
}
