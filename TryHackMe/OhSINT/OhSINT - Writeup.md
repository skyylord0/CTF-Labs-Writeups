# Lab Report - OhSINT

## Overview
- **Category**: OSINT, Steganography, Google Dorking
- **Difficulty**: Easy
- **Platform**: TryHackMe
- **Link**: [https://tryhackme.com/room/ohsint](https://tryhackme.com/room/ohsint)
- **Tags**: #OSINT #Steganography

## Challenge Description
> A beginner-level OSINT challenge. Find as much information as possible from one image.

## Resolution Summary
We are provided with a `.jpg` image. Our goal is to uncover as much information as possible from it. The first step is to check whether the image contains hidden data. By analyzing its metadata, we discover a username and GPS coordinates. These leads allow us to pivot: searching online reveals several social media accounts and posts. With Wigle.net, we trace the SSID of a wireless access point. Finally, by inspecting the source code of the target’s WordPress blog, we uncover a plaintext password.

**This demonstrates how a single file can reveal a surprisingly detailed profile when different pieces of information are connected together.**

## Information Gathering
### Passive Reconnaissance
- First, we download and save the provided image as `OhSINT.jpg`.
    
- A simple visual inspection of the picture does not reveal any obvious clues.
    
- Since images often carry metadata (EXIF data) that can reveal hidden details such as author names, device information, or GPS positions, we attempt to analyze it. We use `exiftool` for this purpose:
    

```bash
exiftool OhSINT.jpg
```

- The tool returns the following relevant entries:
    

```bash
Copyright: OWoodflint
GPS Position: 54 deg 17' 41.27" N, 2 deg 15' 1.33" W
```

- From this output, we immediately extract two useful data points:
    
    - **Potential username**: `OWoodflint`
        
    - **GPS coordinates**: `54°17'41.27" N, 2°15'1.33" W`
        
- By reformatting the coordinates to Google Maps’ accepted format, we confirm the location corresponds to **Hawes, UK**. This provides us with both a possible identity and a geographical location.
    
- Next, we take the username `OWoodflint` and run it through Google searches. This yields several accounts and resources:
    
    - **Twitter/X**: `Oowflint`
        
    - **GitHub**: `OWoodfl1nt`
        
- Exploring these accounts further gives us more leads:
    
    - **Email address**: `OWoodflint@gmail.com` (found on GitHub)
        
    - **WordPress blog**: [oliverwoodflint.wordpress.com](https://oliverwoodflint.wordpress.com/) (found on GitHub)
        
    - **BSSID**: `B4:5D:50:AA:86:41` (found in Twitter/X post)
        
- Having obtained the BSSID, the next logical step is to see if we can identify the SSID associated with it. We use **Wigle.net**, a database that maps wireless networks globally, to perform the lookup. This allows us to confirm the SSID in use:
	
	- **SSID**: `UnileverWiFi`


### Further Investigation
- With the email address, we also test whether it has appeared in past breaches. We check it against **HaveIBeenPwned**, which reveals that it was part of the **Gravatar 2020 breach**. While this does not provide useful credentials for us here, it’s an important reminder of how breached data can become another valuable OSINT pivot point.
    
- As a final step, we investigate the WordPress blog. Simply reading the content does not yield anything useful, so we switch strategies and inspect the **source code of the webpage**. Within the HTML, we find a suspicious entry:
    

```html
<p style="color:#ffffff;" class="has-text-color">pennYDr0pper.!</p>
```

- This is a clear plaintext password embedded directly in the source code. In a real-world scenario, this would represent a major security issue and a critical finding.

## Trophy
- **User profile picture** → `cat`
    
- **City** → `London`
    
- **SSID** → `UnileverWiFi`
    
- **Email** → `OWoodflint@gmail.com`
    
- **Email source** → `GitHub`
    
- **Holiday location** → `New York`
    
- **Password** → `pennYDr0pper.!`
    

## Extra Mile
Once we obtained a set of credentials, an attacker in a real-world engagement could attempt to reuse them across the user’s other platforms (password spraying or credential stuffing). While this may not work in this controlled challenge, it illustrates the danger of password reuse and how one exposed secret can compromise multiple accounts.

## Remediation Summary
- Limit information shared on social media — even small, seemingly harmless posts can be pieced together to form a full profile.
    
- Remove or sanitize metadata from images before publishing them online.
    
- Review and clean up source code before releasing it publicly — never leave hardcoded secrets or debug information exposed.

## Lessons Learned
- **Metadata can leak sensitive data**: EXIF fields may reveal usernames, devices, or GPS locations.
    
- **Pivoting is key in OSINT**: A single username can be enough to uncover multiple accounts and platforms.
    
- **Wigle.net is powerful**: Mapping BSSIDs and SSIDs can tie a digital identity to a physical location.
    
- **Breach checks matter**: Services like HaveIBeenPwned can confirm if personal data has already been exposed.
    
- **Always inspect source code**: Pages sometimes contain hidden information or hardcoded credentials that are not visible in the rendered content.
