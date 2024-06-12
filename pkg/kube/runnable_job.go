package kube

import (
	"context"
	"fmt"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"time"

	"k8s.io/klog"

	"k8s.io/apimachinery/pkg/util/wait"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"

	"github.com/khulnasoft/starboard/pkg/runner"
	batch "k8s.io/api/batch/v1"
	"k8s.io/client-go/kubernetes"
)

var (
	defaultResyncDuration = 30 * time.Minute
)

type runnableJob struct {
	spec      *batch.Job
	clientset kubernetes.Interface
}

// NewRunnableJob constructs a new Runnable task which runs a Kubernetes Job with the given spec and waits for the
// completion or failure.
func NewRunnableJob(clientset kubernetes.Interface, spec *batch.Job) runner.Runnable {
	return &runnableJob{
		spec:      spec,
		clientset: clientset,
	}
}

func (j *runnableJob) Run(ctx context.Context) (err error) {
	informerFactory := informers.NewSharedInformerFactoryWithOptions(
		j.clientset,
		defaultResyncDuration,
		informers.WithNamespace(j.spec.Namespace),
	)
	jobInformer := informerFactory.Batch().V1().Jobs()

	klog.V(3).Infof("Creating runnable job: %s/%s", j.spec.Namespace, j.spec.Name)
	j.spec, err = j.clientset.BatchV1().Jobs(j.spec.Namespace).Create(ctx, j.spec, meta.CreateOptions{})
	if err != nil {
		err = fmt.Errorf("creating job: %w", err)
		return
	}

	complete := make(chan error)

	jobInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(oldObj, newObj interface{}) {
			newJob, ok := newObj.(*batch.Job)
			if !ok {
				return
			}
			if j.spec.UID != newJob.UID {
				return
			}
			if len(newJob.Status.Conditions) == 0 {
				return
			}
			switch condition := newJob.Status.Conditions[0]; condition.Type {
			case batch.JobComplete:
				klog.V(3).Infof("Stopping runnable job on task completion with status: %s", batch.JobComplete)
				complete <- nil
			case batch.JobFailed:
				klog.V(3).Infof("Stopping runnable job on task failure with status: %s", batch.JobFailed)
				complete <- fmt.Errorf("job failed: %s: %s", condition.Reason, condition.Message)
			}
		},
	})

	informerFactory.Start(wait.NeverStop)
	informerFactory.WaitForCacheSync(wait.NeverStop)

	err = <-complete
	return
}
