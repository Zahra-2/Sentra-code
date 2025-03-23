from fastapi import FastAPI, BackgroundTasks, Form
from fastapi.responses import HTMLResponse,FileResponse
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
#from starlette.middleware.sessions import SessionMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.requests import Request
import asyncio
import subprocess

import nmap
from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation
import dns.resolver
import csv
from io import StringIO

from app import report_generator as repoGen


app = FastAPI()
#app.add_middleware(SessionMiddleware, secret_key="secret_key")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Function to run an Nmap scan asynchronously
async def run_nmap(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments="-sV -O")
    nm_results = nm.csv() 
    csv_file = StringIO(nm_results)
    csv_reader = csv.DictReader(csv_file, delimiter=';')
    results = [row for row in csv_reader]
    print(results)
    return results


# Function to run a web vulnerability scan using Wapiti
async def run_web_scan(target):
    
    subprocess.run(f"./env/bin/wapiti -u {str(target)} -p http://192.168.43.1:44355 -f json -o reuslts.json > /dev/null")

# Function to run an SSL scan asynchronously
async def run_ssl_scan(target):
    scanner = Scanner()
    server_location = ServerNetworkLocation(target)
    scan_request = ServerScanRequest(server_location)
    scanner.queue_scans([scan_request])
    scan_result = await asyncio.to_thread(scanner.get_results)  # Run in background
    return scan_result


async def run_dns_scan(target):
    """Performs a DNS lookup and returns the records."""
    record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]
    dns_results = {}

    for record in record_types:
        try:
            answers = dns.resolver.resolve(target, record)

            dns_results[record] = [str(rdata) for rdata in answers]
        except dns.resolver.NoAnswer:
            dns_results[record] = "No record found"
        except dns.resolver.NXDOMAIN:
            return {"error": f"Domain {target} does not exist"}
        except dns.resolver.LifetimeTimeout:
            return {"error": f"Timeout while resolving {target}"}

    return dns_results




# Background task handler
async def perform_scan(target,device_name,device_type):
    results = {}

    results["Nmap"] = await run_nmap(target)
    # results["Nmap"] = nmap_results

    for record in results["Nmap"]:
        if record["port"] == "80" or record["name"] == "http":
            # this scan uses wapit3 binary and the output is a file
            results["WebScan"] = "There is a scan"
            print("running webscan")
            await run_web_scan(target)


        elif record["port"] == "53" :
            results["DNS"] = await run_dns_scan(target)


        elif record["port"] == "443":
            results["SSL"] = await run_ssl_scan(target)

    repoGen.main(results,device_name,device_type,target)
    print(f"Scan complete for {target}")

    # return FileResponse(path=repoGen.FILENAME, filename=repoGen.FILENAME, media_type='application/pdf')
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/service", response_class=HTMLResponse)
async def service(request: Request):
    return templates.TemplateResponse("service.html", {"request": request})


@app.get("/coming-soon", response_class=HTMLResponse)
async def coming_soon(request: Request):
    return templates.TemplateResponse("coming-soon.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
async def register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.get("/manual-connection", response_class=HTMLResponse)
async def manual_connection(request: Request):
    return templates.TemplateResponse("manual-connection.html", {"request": request})

@app.get("/support-team", response_class=HTMLResponse)
async def support(request: Request):
    return templates.TemplateResponse("support-team.html", {"request": request})


@app.get("/welcome", response_class=HTMLResponse)
async def welcome(request: Request):
    return templates.TemplateResponse("welcome.html", {"request": request})


@app.get("/scan-results", response_class=HTMLResponse)
async def scan_results(request: Request):
    return templates.TemplateResponse("scan-results.html", {"request": request})


@app.get("/download")
def download():
    return FileResponse(path=repoGen.FILENAME, filename=repoGen.FILENAME, media_type='application/pdf')


# API endpoint for scanning (Non-blocking)
@app.post("/scan")
async def scan_target(background_tasks: BackgroundTasks, device_name:str = Form(...), device_type:str = Form(...), ip_address: str = Form(...)):
    background_tasks.add_task(perform_scan, ip_address,device_name,device_type)
    print(f"Scan started in the background\nIP address: {ip_address}")
    return RedirectResponse("/service")

#@app.post("/dump")
#async def dump(device_name:str = Form(...), device_type:str = Form(...), ip_address: str = Form(...)):
#    print(ip_address,device_name,device_type)
#    #print(f"Scan started in the background\nIP address: {ip_address}")
#    #RedirectResponse("/service")

