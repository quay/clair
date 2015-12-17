# Notifications

This tool can send notifications to external services when specific events happen, such as vulnerability updates.

For now, it only supports transmitting them to an webhook endpoint using HTTP POST requests, but it can be extended quite easily by registering a new Notifier kind.
To enable the notification system, you simply have to specify the appropriate configuration. See the [example configuration](../config.example.yaml).

# Types of notifications

## A new vulnerability has been released

A notification of this kind is sent as soon as a new vulnerability is added in the system, via the updater or the API.

### Example

```
{  
   "Name":"CVE-2016-0001",
   "Type":"NewVulnerabilityNotification",
   "Content":{  
      "Vulnerability":{  
         "ID":"CVE-2016-0001",
         "Link":"https:security-tracker.debian.org/tracker/CVE-2016-0001",
         "Priority":"Medium",
         "Description":"A futurist vulnerability",
         "AffectedPackages":[  
            {  
               "OS":"centos:6",
               "Name":"bash",
               "AllVersions":true,
               "BeforeVersion":""
            }
         ]
      },
      "IntroducingLayersIDs":[  
         "fb9cc58bde0c0a8fe53e6fdd23898e45041783f2d7869d939d7364f5777fde6f"
      ]
   }
}
```

The `IntroducingLayersIDs` array contains every layers that install at least one affected package.

## A vulnerability's priority has increased

This notification is sent when a vulnerability's priority has increased.

### Example

```
{  
   "Name":"CVE-2016-0001",
   "Type":"VulnerabilityPriorityIncreasedNotification",
   "Content":{  
      "Vulnerability":{  
         "ID":"CVE-2016-0001",
         "Link":"https:security-tracker.debian.org/tracker/CVE-2016-0001",
         "Priority":"Critical",
         "Description":"A futurist vulnerability",
         "AffectedPackages":[  
            {  
               "OS":"centos:6",
               "Name":"bash",
               "AllVersions":true,
               "BeforeVersion":""
            }
         ]
      },
      "OldPriority":"Medium",
      "NewPriority":"Critical",
      "IntroducingLayersIDs":[  
         "fb9cc58bde0c0a8fe53e6fdd23898e45041783f2d7869d939d7364f5777fde6f"
      ]
   }
}
```

The `IntroducingLayersIDs` array contains every layers that install at least one affected package.

## A vulnerability's affected package list changed

This notification is sent when the affected packages of a vulnerability changes.

### Example

```
{  
   "Name":"CVE-2016-0001",
   "Type":"VulnerabilityPackageChangedNotification",
   "Content":{  
      "Vulnerability":{  
         "ID":"CVE-2016-0001",
         "Link":"https:security-tracker.debian.org/tracker/CVE-2016-0001",
         "Priority":"Critical",
         "Description":"A futurist vulnerability",
         "AffectedPackages":[  
            {  
               "OS":"centos:6",
               "Name":"bash",
               "AllVersions":false,
               "BeforeVersion":"4.0"
            }
         ]
      },
      "AddedAffectedPackages":[  
         {  
            "OS":"centos:6",
            "Name":"bash",
            "AllVersions":false,
            "BeforeVersion":"4.0"
         }
      ],
      "RemovedAffectedPackages":[  
         {  
            "OS":"centos:6",
            "Name":"bash",
            "AllVersions":true,
            "BeforeVersion":""
         }
      ],
      "NewIntroducingLayersIDs": [],
      "FormerIntroducingLayerIDs":[  
         "fb9cc58bde0c0a8fe53e6fdd23898e45041783f2d7869d939d7364f5777fde6f",
      ]
   }
}
```

The `NewIntroducingLayersIDs` array contains the layers that install at least one of the newly affected package, and thus which are now vulnerable because of this change. In the other hand, the `FormerIntroducingLayerIDs` array contains the layers that are not introducing the vulnerability anymore.
