# CloudFrunt

CloudFrunt is a tool for identifying misconfigured CloudFront domains.

#### Background

CloudFront is a Content Delivery Network (CDN) provided by Amazon Web Services (AWS). CloudFront users create *distributions* with specific origins to serve content from (an S3 bucket, for example).

Each CloudFront distribution has a unique endpoint (ex. d111111abcdef8.cloudfront.net) that users can point their domains to. These domains need to be listed in the "Alternate Domain Names (CNAMEs)" field for the CloudFront distribution.

When a CloudFront endpoint receives a request, it does NOT automatically serve content from the corresponding distribution. Instead, CloudFront uses the HOST header of the request to determine which distribution to use. This means two things:

1. If the HOST header does not match an entry in the "Alternate Domain Names (CNAMEs)" field of the user's distribution, the request will fail.

2. Any other distribution that contains the specific domain in the HOST header will receive the request and respond to it normally.

This is what allows the domains to be hijacked. There are many cases where a CloudFront user does not to list every domain received in the HOST headers. For example:

* The domain "test.disloops.com" is a CNAME record that points to "disloops.com".
* The "disloops.com" domain is set up to use a CloudFront distribution.
* Because "test.disloops.com" was not added to the "Alternate Domain Names (CNAMEs)" field for the distribution, requests to "test.disloops.com" will fail.
* Another user can create a CloudFront distribution and add "test.disloops.com" to the "Alternate Domain Names (CNAMEs)" field to hijack the domain.

It is bizarre that the unique CloudFront distribution endpoint in the request is effectively ignored. Until that changes...

#### Disclaimer

THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#### Installation

```
$ pip install boto3
$ pip install netaddr
$ pip install dnspython
$ git clone https://github.com/disloops/cloudfrunt.git
$ cd cloudfrunt
$ git clone https://github.com/darkoperator/dnsrecon.git
```

CloudFrunt expects the *dnsrecon* script to be cloned into a subdirectory called *dnsrecon*.

#### Usage

```
cloudfrunt.py [-h] [-l TARGET_FILE] [-d DOMAINS] [-o ORIGIN] [-i ORIGIN_ID] [-s] [-N]

-h, --help                      Show this message and exit
-s, --save                      Save the results to results.txt
-N, --no-dns                    Do not use dnsrecon to expand scope
-l, --target-file TARGET_FILE   File containing a list of domains (one per line)
-d, --domains DOMAINS           Comma-separated list of domains to scan
-o, --origin ORIGIN             Add vulnerable domains to new distributions with this origin
-i, --origin-id ORIGIN_ID       The origin ID to use with new distributions
```

#### Example

```
$ python cloudfrunt.py -o cloudfrunt.com.s3-website-us-east-1.amazonaws.com -i S3-cloudfrunt -s -l list.txt

 [+] Enumerating DNS entries for google.com
 [-] No issues found for google.com

 [+] Enumerating DNS entries for disloops.com
 [+] Found CloudFront domain --> cdn.disloops.com
 [+] Found CloudFront domain --> test.disloops.com
 [-] Potentially misconfigured CloudFront domains:
 [#] --> cdn.disloops.com
 [+] Created new CloudFront distribution EXBC12DE3F45G
 [+] Added cdn.disloops.com to CloudFront distribution EXBC12DE3F45G
 [-] Writing output to results.txt...
```
