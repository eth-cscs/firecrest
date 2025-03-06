# FirecREST version 1

> [!NOTE]
> There is a new version of FirecREST :rocket: [FirecREST version 2](https://github.com/eth-cscs/firecrest-v2) is public since February 2025 and is being activelly deployed by CSCS.

> [!WARNING]
> The development FirecREST version 1 is, thus, only "maintenance" mode (we will fix issues, but with with best effort).
>
> We strongly recommend to move your code to FirecREST-v2

> [!IMPORTANT]
> If you are new to FirecREST, please redirect yourself to version 2 repository.

 


FirecREST platform, a RESTful Services Gateway to High-Performance Computing (HPC) resources, is a high-performance and reusable framework that integrates with existing HPC infrastructure, thus enabling the access to HPC resources to web-enabled services.

FirecREST provides a REST API that defines a set of HTTP methods through which developers can interact with using the HTTP/REST protocol architecture. Calls to the REST API received are translated into the appropriate infrastructure requests. Among the most prominent services that FirecREST exposes we find authentication and authorization, execution of parallel jobs through a workload manager, file-system operations, data mover, system status, system's job accounting information, etc.

All the endpoints are listed in FirecREST's [OpenAPI specification](https://firecrest-docs.v1.svc.cscs.ch/). You can also find more information on its services and examples in our [documentation](https://firecrest.readthedocs.io).

## FirecREST demo

To run a local install of FirecREST and a demo client see [deploy/demo/README.md](deploy/demo/README.md)
