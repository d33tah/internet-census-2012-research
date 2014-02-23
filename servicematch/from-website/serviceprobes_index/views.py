from django.shortcuts import render
from models import TableEntry
from django.db.models import Sum, Count

def index(request):

  product_counts = list(TableEntry
                        .objects
                        .values('product_name')
                        .annotate(count=Sum('count'))
                        .annotate(port_count=Count('portno', distinct=True))
                        .order_by('-count')
                       )

  return render(request, 'index_template.html', {'data': product_counts})
