# FirecREST version 1

> [!IMPORTANT]
> There is a new version of FirecREST :rocket: [FirecREST version 2](https://github.com/eth-cscs/firecrest-v2) is public since February 2025 and it's being actively deployed by CSCS.

> [!WARNING]
> FirecREST version 1 is now in maintenance mode. Only minimal-effort issue fixes will be addressed, and no new features are planned.

> [!TIP]
> If you are new to FirecREST, please start directly with [version 2](https://github.com/eth-cscs/firecrest-v2).
> If you already use FirecREST v1, we strongly recommend to move your code to FirecREST-v2.

FirecREST platform, a RESTful Services Gateway to High-Performance Computing (HPC) resources, is a high-performance and reusable framework that integrates with existing HPC infrastructure, thus enabling the access to HPC resources to web-enabled services.

FirecREST provides a REST API that defines a set of HTTP methods through which developers can interact with using the HTTP/REST protocol architecture. Calls to the REST API received are translated into the appropriate infrastructure requests. Among the most prominent services that FirecREST exposes we find authentication and authorization, execution of parallel jobs through a workload manager, file-system operations, data mover, system status, system's job accounting information, etc.

All the endpoints are listed in FirecREST's [OpenAPI specification](https://firecrest-docs.v1.svc.cscs.ch/). You can also find more information on its services and examples in our [documentation](https://firecrest.readthedocs.io).

## FirecREST demo

To run a local install of FirecREST and a demo client see [deploy/demo/README.md](deploy/demo/README.md)
